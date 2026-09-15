use crate::{admission::{AdmissionGrant, AdmissionTrust}, Error};
use serde::{Deserialize, Serialize};
use std::path::Path;

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

pub fn policy_digest(_policy: &AllocationPolicy) -> Result<String, Error> { Err(Error::UnsupportedCapability) }
pub fn allocation_bytes(_request: &AllocationRequest) -> Result<Vec<u8>, Error> { Err(Error::UnsupportedCapability) }

pub struct AllocationLedger;

impl AllocationLedger {
    pub fn open(_path: impl AsRef<Path>, _trust: AdmissionTrust, _policy: AllocationPolicy) -> Result<Self, Error> { Ok(Self) }
    pub fn reserve(&mut self, _grant: &AdmissionGrant, _request: &AllocationRequest, _clock: impl Fn() -> u64) -> Result<Reservation, Error> { Err(Error::UnsupportedCapability) }
    pub fn balance(&self, _member_id: &str) -> Result<Option<u64>, Error> { Err(Error::UnsupportedCapability) }
    /// No deployed proof backend currently binds a hidden answer/close receipt
    /// to the debited member without enabling pooled credits.
    pub fn resolve_private(&mut self, _proof: &[u8]) -> Result<(), Error> { Err(Error::UnsupportedCapability) }
}
