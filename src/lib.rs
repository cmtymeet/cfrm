//! Authenticated public presence and private introduction-allocation boundaries.
//! No profile content, messages, recipient IDs or relationship map belong here.

pub mod accounting;
#[cfg(feature = "sqlite")]
pub mod accounting_ledger;
#[cfg(all(feature = "sqlite", not(target_arch = "wasm32")))]
pub mod accounting_service;
mod accounting_policy;
pub mod admission;
#[cfg(feature = "sqlite")]
pub mod allocation;
pub mod board;
pub mod discovery;
pub mod discovery_store;
#[cfg(feature = "sqlite")]
pub mod discovery_control;
#[cfg(all(feature = "discovery-api", not(target_arch = "wasm32")))]
pub mod discovery_api;
#[cfg(all(feature = "discovery-valkey", not(target_arch = "wasm32")))]
pub mod discovery_valkey;
#[cfg(all(feature = "browser", target_arch = "wasm32"))]
pub mod browser;
#[cfg(all(feature = "permit-issuer", not(target_arch = "wasm32")))]
pub mod permit_issuer;
#[cfg(feature = "permits")]
pub mod permits;
#[cfg(feature = "permits")]
pub mod key_access;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    Admission,
    Signature,
    Expired,
    ClockRollback,
    Replay,
    Capacity,
    NoAllowance,
    PolicyMismatch,
    Storage,
    UnsupportedCapability,
    CryptoProvider,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}
