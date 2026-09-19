//! Pooled Valkey discovery storage. The service verifies signatures before this
//! adapter atomically commits per-member state and live-index changes.
use crate::{
    admission::{digest, scope},
    discovery::{CachedProfile, DiscoveryLimits, DiscoveryOperation, DiscoveryResponse,
        DiscoveryStore, VerifiedDiscoveryRequest},
    discovery_store::{summary, transition, MemberControl},
    Error,
};
use redis::ConnectionLike;
use std::time::Duration;

/// Runtime credentials belong in the supplied URL, never logs or browser config.
pub struct ValkeyConfig {
    pub url: String,
    pub namespace: String,
    pub pool_size: u32,
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub pool_timeout: Duration,
    pub max_cas_attempts: usize,
    /// Test-only loopback connections may omit TLS; remote connections may not.
    pub allow_plaintext_loopback: bool,
    pub root_certificate_pem: Option<Vec<u8>>,
}

struct Manager {
    client: redis::Client,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl r2d2::ManageConnection for Manager {
    type Connection = redis::Connection;
    type Error = redis::RedisError;
    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let connection = self.client.get_connection_with_timeout(self.connect_timeout)?;
        connection.set_read_timeout(Some(self.io_timeout))?;
        connection.set_write_timeout(Some(self.io_timeout))?;
        Ok(connection)
    }
    fn is_valid(&self, connection: &mut Self::Connection) -> Result<(), Self::Error> {
        redis::cmd("PING").query::<String>(connection).map(|_| ())
    }
    fn has_broken(&self, connection: &mut Self::Connection) -> bool { !connection.is_open() }
}

/// Every operation uses a bounded shared pool, not a connection per member.
pub struct ValkeyDiscoveryStore {
    pool: r2d2::Pool<Manager>,
    namespace: String,
    pool_timeout: Duration,
    max_cas_attempts: usize,
}

const COMMIT: &str = r#"
local existing = redis.call('GET', KEYS[1]) or ''
if existing ~= ARGV[1] then return 0 end
local now = tonumber(ARGV[3])
local last = tonumber(redis.call('GET', KEYS[6]) or '0')
if now < last then return 2 end
redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', now)
if existing == '' and redis.call('ZCARD', KEYS[4]) >= tonumber(ARGV[6]) then return 3 end
local ttl = tonumber(ARGV[4])
local clock_ttl = math.max(ttl, redis.call('TTL', KEYS[6]))
redis.call('SET', KEYS[1], ARGV[2], 'EX', ttl)
redis.call('ZADD', KEYS[4], now + ttl, ARGV[7])
redis.call('SET', KEYS[6], ARGV[3], 'EX', clock_ttl)
local live = tonumber(ARGV[5])
if live > now then
  if ARGV[8] ~= '' then redis.call('SET', KEYS[2], ARGV[8], 'EX', live-now) end
  if redis.call('EXISTS', KEYS[2]) == 1 then
    redis.call('EXPIRE', KEYS[2], live-now)
    redis.call('ZADD', KEYS[3], 0, ARGV[7])
    redis.call('ZADD', KEYS[5], live, ARGV[7])
  else
    redis.call('ZREM', KEYS[3], ARGV[7])
    redis.call('ZREM', KEYS[5], ARGV[7])
  end
else
  redis.call('DEL', KEYS[2])
  redis.call('ZREM', KEYS[3], ARGV[7])
  redis.call('ZREM', KEYS[5], ARGV[7])
end
for _, i in ipairs({3,4,5}) do
  if redis.call('TTL', KEYS[i]) < ttl then redis.call('EXPIRE', KEYS[i], ttl) end
end
return 1
"#;

// Reads never attach reader identities to target keys or index observations.
const FETCH: &str = r#"
local until_at = tonumber(redis.call('ZSCORE', KEYS[2], ARGV[1]) or '0')
if until_at <= tonumber(ARGV[2]) then return nil end
return redis.call('GET', KEYS[1])
"#;

impl ValkeyDiscoveryStore {
    pub fn connect(config: ValkeyConfig) -> Result<Self, Error> {
        if !scope(&config.namespace) || config.pool_size == 0 || config.pool_size > 1024
            || config.connect_timeout.is_zero() || config.io_timeout.is_zero()
            || config.pool_timeout.is_zero() || config.max_cas_attempts == 0
            || config.max_cas_attempts > 100 { return Err(Error::InvalidInput); }
        let info = redis::Client::open(config.url.as_str()).map_err(|_| Error::Storage)?;
        match &info.get_connection_info().addr {
            redis::ConnectionAddr::TcpTls { insecure: false, .. } => (),
            redis::ConnectionAddr::Tcp(host, _) if config.allow_plaintext_loopback &&
                matches!(host.as_str(), "127.0.0.1" | "::1") => (),
            _ => return Err(Error::InvalidInput),
        }
        let client = if config.root_certificate_pem.is_some() {
            redis::Client::build_with_tls(config.url.as_str(), redis::TlsCertificates {
                client_tls: None, root_cert: config.root_certificate_pem,
            }).map_err(|_| Error::Storage)?
        } else { info };
        let manager = Manager { client, connect_timeout: config.connect_timeout, io_timeout: config.io_timeout };
        let pool = r2d2::Pool::builder().max_size(config.pool_size).min_idle(Some(0))
            .connection_timeout(config.pool_timeout).build(manager).map_err(|_| Error::Storage)?;
        Ok(Self { pool, namespace: config.namespace, pool_timeout: config.pool_timeout,
            max_cas_attempts: config.max_cas_attempts })
    }

    fn prefix(&self, community: &str) -> String {
        format!("cfrm:{{{}}}", digest(format!("{}\0{}", self.namespace, community).as_bytes()))
    }

    fn fetch(&self, connection: &mut redis::Connection, prefix: &str, member: &str, now: u64)
        -> Result<Option<CachedProfile>, Error> {
        let body: Option<String> = redis::Script::new(FETCH)
            .key(format!("{prefix}:profile:{member}"))
            .key(format!("{prefix}:live")).arg(member).arg(now).invoke(connection)
            .map_err(|_| Error::Storage)?;
        body.map(|value| serde_json::from_str(&value).map_err(|_| Error::Storage)).transpose()
    }
}

impl DiscoveryStore for ValkeyDiscoveryStore {
    fn execute(&self, request: &VerifiedDiscoveryRequest, limits: &DiscoveryLimits, now: u64)
        -> Result<DiscoveryResponse, Error> {
        let mut connection = self.pool.get_timeout(self.pool_timeout).map_err(|_| Error::Capacity)?;
        let prefix = self.prefix(&request.community_id);
        let control_key = format!("{prefix}:control:{}", request.member_id);
        let profile_key = format!("{prefix}:profile:{}", request.member_id);
        let catalog_key = format!("{prefix}:catalog");
        let controls_key = format!("{prefix}:controls");
        let live_key = format!("{prefix}:live");
        let clock_key = format!("{prefix}:clock");
        let mut committed = false;
        for _ in 0..self.max_cas_attempts {
            let previous: Option<String> = redis::cmd("GET").arg(&control_key).query(&mut *connection)
                .map_err(|_| Error::Storage)?;
            let state = previous.as_ref().map(|value| serde_json::from_str::<MemberControl>(value)
                .map_err(|_| Error::Storage)).transpose()?.unwrap_or_default();
            let change = transition(state, request, limits, now)?;
            if change.retry { return Ok(DiscoveryResponse::Updated); }
            let body = change.publication.as_ref().map(serde_json::to_string).transpose()
                .map_err(|_| Error::InvalidInput)?.unwrap_or_default();
            let value = serde_json::to_string(&change.control).map_err(|_| Error::Storage)?;
            let result: i32 = redis::Script::new(COMMIT).key(&control_key).key(&profile_key)
                .key(&catalog_key).key(&controls_key).key(&live_key).key(&clock_key)
                .arg(previous.unwrap_or_default()).arg(value).arg(now)
                .arg(change.control.retain_until.saturating_sub(now).max(1))
                .arg(change.control.live_until(now)).arg(limits.max_members).arg(&request.member_id)
                .arg(body).invoke(&mut *connection).map_err(|_| Error::Storage)?;
            match result {
                0 => continue,
                1 => { committed = true; break; },
                2 => return Err(Error::ClockRollback),
                3 => return Err(Error::Capacity),
                _ => return Err(Error::Storage),
            }
        }
        if !committed { return Err(Error::Capacity); }
        match &request.operation {
            DiscoveryOperation::Fetch { member_id } => Ok(DiscoveryResponse::Profile {
                publication: self.fetch(&mut connection, &prefix, member_id, now)?,
            }),
            DiscoveryOperation::Query { filters, limit, after } => {
                let lower = after.as_ref().map(|cursor| format!("({cursor}")).unwrap_or_else(|| "-".into());
                let candidates: Vec<String> = redis::cmd("ZRANGEBYLEX").arg(&catalog_key)
                    .arg(lower).arg("+").arg("LIMIT").arg(0).arg(limits.max_scan + 1)
                    .query(&mut *connection).map_err(|_| Error::Storage)?;
                let mut entries = Vec::new();
                let mut scanned = 0;
                let mut last = None;
                let mut more = false;
                for member in candidates {
                    if scanned >= limits.max_scan || entries.len() >= *limit { more = true; break; }
                    scanned += 1;
                    last = Some(member.clone());
                    if let Some(publication) = self.fetch(&mut connection, &prefix, &member, now)? {
                        if filters.iter().all(|(key, value)| publication.envelope.discriminators.get(key) == Some(value)) {
                            let until: Option<u64> = redis::cmd("ZSCORE").arg(&live_key).arg(&member)
                                .query(&mut *connection).map_err(|_| Error::Storage)?;
                            if let Some(until) = until.filter(|until| *until > now) {
                                entries.push(summary(&publication, until));
                            }
                        }
                    } else {
                        // Only delete an index row if it is still expired atomically.
                        let _: i32 = redis::Script::new("local v=tonumber(redis.call('ZSCORE',KEYS[2],ARGV[1]) or '0'); if v<=tonumber(ARGV[2]) or redis.call('EXISTS',KEYS[3])==0 then redis.call('ZREM',KEYS[1],ARGV[1]); redis.call('ZREM',KEYS[2],ARGV[1]); end; return 1")
                            .key(&catalog_key).key(&live_key).key(format!("{prefix}:profile:{member}"))
                            .arg(&member).arg(now).invoke(&mut *connection).map_err(|_| Error::Storage)?;
                    }
                }
                Ok(DiscoveryResponse::Page { entries, next_cursor: if more { last } else { None } })
            }
            _ => Ok(DiscoveryResponse::Updated),
        }
    }
}
