//! Synthetic public-enrollment fixture ONLY. No network or production issuer.
//! Uses the existing cmsg root/device wire and real strict Ed25519 verification.
use cfrm::admission::{
    admission_bytes, device_authorization_bytes, member_id, verify_admission,
    verify_device_authorization, AdmissionGrant, AdmissionTrust, DeviceAuthorization,
};
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER as HEX};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{BufRead, Read, Write};

const COMMUNITY: &str = "synthetic-accounting-community";
const NOW: u64 = 100;
const START: u64 = 80;
const END: u64 = 1000;

type Result<T> = std::result::Result<T, String>;
fn hash(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn decode<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = HEX.decode(text.as_bytes()).map_err(|_| "hex")?;
    if HEX.encode(&bytes) != text {
        return Err("noncanonical hex".into());
    }
    bytes.try_into().map_err(|_| "length".into())
}
fn b64<const N: usize>(text: &str) -> Result<[u8; N]> {
    let bytes = B64.decode(text.as_bytes()).map_err(|_| "base64")?;
    if B64.encode(&bytes) != text {
        return Err("noncanonical base64".into());
    }
    bytes.try_into().map_err(|_| "length".into())
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicKey {
    account_key: String,
    secret_hash: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Enrollment {
    admission: AdmissionGrant,
    authorization: DeviceAuthorization,
    account_key: String,
    secret_hash: String,
    issued_at: u64,
    expires_at: u64,
    signature: String,
}
fn enrollment_bytes(e: &Enrollment) -> Result<Vec<u8>> {
    decode::<64>(&e.account_key)?;
    decode::<32>(&e.secret_hash)?;
    if e.issued_at != START || e.expires_at != END {
        return Err("fixture time bounds".into());
    }
    serde_json::to_vec(&json!([
        "cfrm.accounting-enrollment.spike.v1",
        COMMUNITY,
        e.admission.member_id,
        e.account_key,
        e.secret_hash,
        e.issued_at,
        e.expires_at
    ]))
    .map_err(|_| "canonical enrollment".into())
}
fn trust() -> AdmissionTrust {
    AdmissionTrust {
        community_id: COMMUNITY.into(),
        policy_digest: B64.encode(&hash(b"synthetic-accounting-policy")),
        issuer_public_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes(),
    }
}
fn make(index: usize, key: &PublicKey) -> Result<Enrollment> {
    let root = SigningKey::from_bytes(&[50 + index as u8; 32]);
    let device = SigningKey::from_bytes(&[60 + index as u8; 32]);
    let issuer = SigningKey::from_bytes(&[17; 32]);
    let t = trust();
    let root_key = B64.encode(&root.verifying_key().to_bytes());
    let mut admission = AdmissionGrant {
        version: 1,
        issuer_key_id: B64.encode(&hash(t.issuer_public_key)),
        community_id: COMMUNITY.into(),
        member_id: member_id(COMMUNITY, &root_key).map_err(|_| "root identity")?,
        chat_public_key: B64.encode(&device.verifying_key().to_bytes()),
        policy_digest: t.policy_digest,
        issued_at: START,
        expires_at: END,
        signature: String::new(),
    };
    admission.signature = B64.encode(
        &issuer
            .sign(&admission_bytes(&admission).map_err(|_| "admission")?)
            .to_bytes(),
    );
    let mut authorization = DeviceAuthorization {
        version: 1,
        community_id: COMMUNITY.into(),
        member_id: admission.member_id.clone(),
        root_public_key: root_key,
        device_public_key: admission.chat_public_key.clone(),
        issued_at: START,
        expires_at: END,
        signature: String::new(),
    };
    authorization.signature = B64.encode(
        &root
            .sign(&device_authorization_bytes(&authorization).map_err(|_| "device")?)
            .to_bytes(),
    );
    let mut e = Enrollment {
        admission,
        authorization,
        account_key: key.account_key.clone(),
        secret_hash: key.secret_hash.clone(),
        issued_at: START,
        expires_at: END,
        signature: String::new(),
    };
    e.signature = B64.encode(&device.sign(&enrollment_bytes(&e)?).to_bytes());
    Ok(e)
}
fn leaf(e: &Enrollment) -> Result<[u8; 32]> {
    let mut bytes = vec![1];
    bytes.extend(hash(COMMUNITY));
    bytes.extend(b64::<32>(&e.admission.member_id)?);
    bytes.extend(decode::<64>(&e.account_key)?);
    bytes.extend(decode::<32>(&e.secret_hash)?);
    bytes.extend(e.issued_at.to_be_bytes());
    bytes.extend(e.expires_at.to_be_bytes());
    Ok(hash(bytes))
}
fn node(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut bytes = vec![6];
    bytes.extend(a);
    bytes.extend(b);
    hash(bytes)
}
fn verify(entries: &[Enrollment]) -> Result<Value> {
    if entries.len() != 4 {
        return Err("fixture roster has exactly four roots".into());
    }
    let mut seen = BTreeSet::new();
    let mut leaves = Vec::new();
    for (index, e) in entries.iter().enumerate() {
        verify_admission(&e.admission, &trust(), NOW).map_err(|_| "eligibility")?;
        verify_admission(&e.admission, &trust(), e.issued_at)
            .map_err(|_| "backdated eligibility")?;
        verify_device_authorization(&e.authorization, &e.admission, NOW)
            .map_err(|_| "member-owned device")?;
        verify_device_authorization(&e.authorization, &e.admission, e.issued_at)
            .map_err(|_| "backdated enrollment")?;
        // This test checkpoint has a pinned complete roster, not issuer-supplied
        // membership. Production completeness/consistency remains an open contract.
        let expected = SigningKey::from_bytes(&[50 + index as u8; 32]);
        let expected_id = member_id(COMMUNITY, &B64.encode(&expected.verifying_key().to_bytes()))
            .map_err(|_| "root")?;
        if e.admission.member_id != expected_id || !seen.insert(expected_id) {
            return Err("roster/root substitution".into());
        }
        let device = VerifyingKey::from_bytes(&b64::<32>(&e.authorization.device_public_key)?)
            .map_err(|_| "device key")?;
        if device.is_weak() {
            return Err("weak device".into());
        }
        device
            .verify_strict(
                &enrollment_bytes(e)?,
                &Signature::from_bytes(&b64::<64>(&e.signature)?),
            )
            .map_err(|_| "delegation signature")?;
        leaves.push(leaf(e)?);
    }
    let left = node(leaves[0], leaves[1]);
    let right = node(leaves[2], leaves[3]);
    Ok(
        json!({ "community": HEX.encode(&hash(COMMUNITY)), "root": HEX.encode(&node(left, right)),
        "now": NOW, "entries": entries, "leaves": leaves.iter().map(|v| HEX.encode(v)).collect::<Vec<_>>() }),
    )
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum Command {
    Enroll { keys: Vec<PublicKey> },
    Verify { entries: Vec<Enrollment> },
}
fn command(c: Command) -> Result<Value> {
    match c {
        Command::Enroll { keys } => {
            if keys.len() != 4 {
                return Err("four public keys required".into());
            }
            let entries = keys
                .iter()
                .enumerate()
                .map(|(i, k)| make(i, k))
                .collect::<Result<Vec<_>>>()?;
            verify(&entries)
        }
        Command::Verify { entries } => verify(&entries),
    }
}
fn main() -> std::io::Result<()> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    for _ in 0..32 {
        let mut line = Vec::new();
        let n = input.by_ref().take(65_537).read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        if line.len() > 65_536 || line.last() != Some(&b'\n') {
            return Err(std::io::Error::other("fixture input bound"));
        }
        let result = serde_json::from_slice::<Command>(&line)
            .map_err(|_| "command".into())
            .and_then(command);
        let response = match result {
            Ok(value) => json!({"ok": true, "value": value}),
            Err(error) => json!({"ok": false, "error": error}),
        };
        serde_json::to_writer(&mut output, &response)?;
        output.write_all(b"\n")?;
        output.flush()?;
    }
    Ok(())
}
