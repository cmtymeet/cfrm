use crate::{admission::{AdmissionGrant, AdmissionTrust}, Error};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OnionEndpoint { pub host: String, pub port: u16 }

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PresenceUpdate {
    pub community_id: String,
    pub member_id: String,
    pub chat_public_key: String,
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub endpoint: Option<OnionEndpoint>,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct BoardLimits {
    pub max_members: usize,
    pub max_devices_per_member: usize,
    pub max_lease_seconds: u64,
    pub max_replay_entries: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DevicePresence { pub chat_public_key: String, pub endpoint: OnionEndpoint, pub expires_at: u64 }

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberPresence { pub member_id: String, pub devices: Vec<DevicePresence> }

pub fn presence_bytes(_update: &PresenceUpdate) -> Result<Vec<u8>, Error> { Err(Error::UnsupportedCapability) }

pub struct MeetingBoard;

impl MeetingBoard {
    pub fn new(_trust: AdmissionTrust, _limits: BoardLimits) -> Result<Self, Error> { Ok(Self) }
    pub fn apply(&mut self, _grant: &AdmissionGrant, _update: &PresenceUpdate, _now: u64) -> Result<(), Error> { Err(Error::UnsupportedCapability) }
    pub fn snapshot(&mut self, _now: u64) -> Result<Vec<MemberPresence>, Error> { Err(Error::UnsupportedCapability) }
}
