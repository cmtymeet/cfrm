use crate::{admission::{decode, digest, signature, verify_admission, verify_device_authorization, AdmissionGrant, AdmissionTrust, DeviceAuthorization, MAX_INTEGER}, Error};
use serde::{Deserialize, Serialize};
use data_encoding::BASE64URL_NOPAD;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationPolicy {
    pub initial_credits: u64,
    pub periodic_credits: u64,
    pub period_seconds: u64,
    pub credit_cap: u64,
    pub max_authorization_seconds: u64,
    pub max_request_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllocationRequest {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub policy_digest: String,
    pub nonce: String,
    pub blinded_request: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation { pub request_digest: String, pub remaining_credits: u64 }

pub fn policy_digest(policy: &AllocationPolicy) -> Result<String, Error> {
    if policy.period_seconds == 0 || policy.initial_credits > policy.credit_cap || policy.periodic_credits > policy.credit_cap || policy.credit_cap > MAX_INTEGER || policy.period_seconds > MAX_INTEGER || policy.max_authorization_seconds == 0 || policy.max_authorization_seconds > MAX_INTEGER || policy.max_request_bytes == 0 || policy.max_request_bytes > usize::MAX / 2 { return Err(Error::InvalidInput); }
    let bytes = serde_json::to_vec(&serde_json::json!(["cfrm.allocation.policy.v1", policy])).map_err(|_| Error::InvalidInput)?;
    Ok(digest(&bytes))
}

pub fn allocation_bytes(request: &AllocationRequest) -> Result<Vec<u8>, Error> {
    if !crate::admission::scope(&request.community_id) || request.issued_at == 0 || request.issued_at >= request.expires_at || request.expires_at > MAX_INTEGER { return Err(Error::InvalidInput); }
    for value in [&request.member_id, &request.chat_public_key, &request.policy_digest, &request.nonce] { decode::<32>(value)?; }
    let blinded = BASE64URL_NOPAD.decode(request.blinded_request.as_bytes()).map_err(|_| Error::InvalidInput)?;
    if blinded.is_empty() || BASE64URL_NOPAD.encode(&blinded) != request.blinded_request { return Err(Error::InvalidInput); }
    serde_json::to_vec(&serde_json::json!(["cfrm.allocation.reserve.v1", request.community_id, request.member_id, request.chat_public_key, request.policy_digest, request.nonce, digest(&blinded), request.issued_at, request.expires_at])).map_err(|_| Error::InvalidInput)
}

/// Operator-side authoritative reservations, not a proof of a sent/read message.
/// This database contains a member's allowance and blinded-request digests only.
/// It has no recipient, conversation, device-count multiplier or client counters.
pub struct AllocationLedger {
    connection: Connection,
    trust: AdmissionTrust,
    policy: AllocationPolicy,
    policy_digest: String,
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self { Self::Storage }
}

impl AllocationLedger {
    pub fn open(path: impl AsRef<Path>, trust: AdmissionTrust, policy: AllocationPolicy) -> Result<Self, Error> {
        let policy_digest = policy_digest(&policy)?;
        if !crate::admission::scope(&trust.community_id) { return Err(Error::InvalidInput); }
        decode::<32>(&trust.policy_digest)?;
        let mut connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS cfrm_allocation_config (singleton INTEGER PRIMARY KEY CHECK(singleton=1), config TEXT NOT NULL, clock_floor INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS cfrm_allocation_members (member TEXT PRIMARY KEY, credits INTEGER NOT NULL CHECK(credits>=0), last_period INTEGER NOT NULL) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS cfrm_allocation_reservations (member TEXT NOT NULL REFERENCES cfrm_allocation_members(member), nonce TEXT NOT NULL, request_digest TEXT NOT NULL, remaining INTEGER NOT NULL, PRIMARY KEY(member,nonce)) WITHOUT ROWID;")?;
        let config = serde_json::to_string(&serde_json::json!(["cfrm.allocation.database.v1", trust.community_id, trust.policy_digest, BASE64URL_NOPAD.encode(&trust.issuer_public_key), policy_digest])).map_err(|_| Error::InvalidInput)?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let prior: Option<String> = transaction.query_row("SELECT config FROM cfrm_allocation_config WHERE singleton=1", [], |row| row.get(0)).optional()?;
        if let Some(prior) = prior { if prior != config { return Err(Error::PolicyMismatch); } }
        else { transaction.execute("INSERT INTO cfrm_allocation_config(singleton,config,clock_floor) VALUES(1,?1,0)", [&config])?; }
        transaction.commit()?;
        Ok(Self { connection, trust, policy, policy_digest })
    }

    /// Reserve exactly one issuance unit. The trusted issuer consumes the result
    /// for the exact blinded request; this is not a redeemable introduction token.
    /// The same signed request recovers its original result without another debit.
    pub fn reserve(&mut self, grant: &AdmissionGrant, authorization: &DeviceAuthorization, request: &AllocationRequest, clock: impl Fn() -> u64) -> Result<Reservation, Error> {
        let before = clock();
        verify_admission(grant, &self.trust, before)?;
        verify_device_authorization(authorization, grant, before)?;
        if request.community_id != grant.community_id || request.member_id != grant.member_id || request.chat_public_key != grant.chat_public_key || request.policy_digest != self.policy_digest { return Err(Error::Admission); }
        if request.blinded_request.len() > self.policy.max_request_bytes * 2 { return Err(Error::InvalidInput); }
        let bytes = allocation_bytes(request)?;
        if BASE64URL_NOPAD.decode(request.blinded_request.as_bytes()).map_err(|_| Error::InvalidInput)?.len() > self.policy.max_request_bytes { return Err(Error::InvalidInput); }
        if request.expires_at - request.issued_at > self.policy.max_authorization_seconds || request.expires_at > grant.expires_at || request.expires_at > authorization.expires_at || before < request.issued_at || before >= request.expires_at { return Err(Error::Expired); }
        signature(&request.chat_public_key, &bytes, &request.signature)?;
        let request_digest = digest(&bytes);
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // A competing writer may hold the lock until the authorization expires.
        // Sample trusted time again under the lock, before every new effect.
        let now = clock();
        let floor: u64 = transaction.query_row("SELECT clock_floor FROM cfrm_allocation_config WHERE singleton=1", [], |row| row.get(0))?;
        if now < floor || now < before || now > MAX_INTEGER { return Err(Error::ClockRollback); }
        if now < request.issued_at || now >= request.expires_at || now >= grant.expires_at || now >= authorization.expires_at { return Err(Error::Expired); }
        let prior: Option<(String, u64)> = transaction.query_row("SELECT request_digest,remaining FROM cfrm_allocation_reservations WHERE member=?1 AND nonce=?2", params![request.member_id,request.nonce], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((prior, remaining_credits)) = prior {
            if prior != request_digest { return Err(Error::Replay); }
            transaction.execute("UPDATE cfrm_allocation_config SET clock_floor=?1 WHERE singleton=1", [now])?;
            transaction.commit()?;
            return Ok(Reservation { request_digest, remaining_credits });
        }
        let period = now / self.policy.period_seconds;
        let account: Option<(u64,u64)> = transaction.query_row("SELECT credits,last_period FROM cfrm_allocation_members WHERE member=?1", [&request.member_id], |row| Ok((row.get(0)?,row.get(1)?))).optional()?;
        let credits = match account {
            Some((credits,last_period)) => {
                let elapsed = period.checked_sub(last_period).ok_or(Error::ClockRollback)?;
                credits.saturating_add(elapsed.saturating_mul(self.policy.periodic_credits)).min(self.policy.credit_cap)
            },
            None => self.policy.initial_credits,
        };
        let remaining_credits = credits.checked_sub(1).ok_or(Error::NoAllowance)?;
        transaction.execute("INSERT INTO cfrm_allocation_members(member,credits,last_period) VALUES(?1,?2,?3) ON CONFLICT(member) DO UPDATE SET credits=excluded.credits,last_period=excluded.last_period", params![request.member_id,remaining_credits,period])?;
        transaction.execute("INSERT INTO cfrm_allocation_reservations(member,nonce,request_digest,remaining) VALUES(?1,?2,?3,?4)", params![request.member_id,request.nonce,request_digest,remaining_credits])?;
        transaction.execute("UPDATE cfrm_allocation_config SET clock_floor=?1 WHERE singleton=1", [now])?;
        transaction.commit()?;
        Ok(Reservation { request_digest, remaining_credits })
    }

    /// Trusted local storage diagnostic, not an unauthenticated network endpoint.
    pub fn balance(&self, member_id: &str) -> Result<Option<u64>, Error> {
        decode::<32>(member_id)?;
        self.connection.query_row("SELECT credits FROM cfrm_allocation_members WHERE member=?1", [member_id], |row| row.get(0)).optional().map_err(Into::into)
    }
    /// No deployed proof backend currently binds a hidden answer/close receipt
    /// to the debited member without enabling pooled credits.
    pub fn resolve_private(&mut self, _proof: &[u8]) -> Result<(), Error> { Err(Error::UnsupportedCapability) }
}
