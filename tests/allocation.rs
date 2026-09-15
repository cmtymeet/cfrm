#![cfg(feature = "sqlite")]
mod common;
use cfrm::{allocation::{AllocationLedger, AllocationPolicy, AllocationRequest, policy_digest}, Error};
use common::{encoded,Fixture};
use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer,SigningKey};
use sha2::{Digest,Sha256};

fn policy() -> AllocationPolicy { AllocationPolicy { initial_credits: 2, periodic_credits: 1, period_seconds: 100, credit_cap: 3, max_authorization_seconds: 60, max_request_bytes: 1024 } }
fn request(f:&Fixture,key:&SigningKey,nonce:u8,now:u64)->AllocationRequest {
    let mut request=AllocationRequest { community_id:f.trust.community_id.clone(),member_id:encoded(5),chat_public_key:BASE64URL_NOPAD.encode(&key.verifying_key().to_bytes()),policy_digest:policy_digest(&policy()).unwrap(),nonce:encoded(nonce),blinded_request:BASE64URL_NOPAD.encode(&[nonce;384]),issued_at:now,expires_at:now+40,signature:String::new() };
    let hash=BASE64URL_NOPAD.encode(&Sha256::digest(BASE64URL_NOPAD.decode(request.blinded_request.as_bytes()).unwrap()));
    let bytes=serde_json::to_vec(&serde_json::json!(["cfrm.allocation.reserve.v1",request.community_id,request.member_id,request.chat_public_key,request.policy_digest,request.nonce,hash,request.issued_at,request.expires_at])).unwrap();
    request.signature=BASE64URL_NOPAD.encode(&key.sign(&bytes).to_bytes());request
}

#[test]
fn devices_share_one_durable_balance_and_identical_retry_does_not_debit() {
    let f=Fixture::new();let dir=tempfile::tempdir().unwrap();let path=dir.path().join("state.sqlite");
    let req=request(&f,&f.device,10,110);
    let first={let mut ledger=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();ledger.reserve(&f.grant(5,&f.device),&req,||110).unwrap()};
    assert_eq!(first.remaining_credits,1);
    let second=SigningKey::from_bytes(&[7;32]);
    let mut ledger=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();
    assert_eq!(ledger.reserve(&f.grant(5,&f.device),&req,||111).unwrap(),first);
    ledger.reserve(&f.grant(5,&second),&request(&f,&second,11,111),||111).unwrap();
    assert_eq!(ledger.balance(&encoded(5)).unwrap(),Some(0));
    assert_eq!(ledger.reserve(&f.grant(5,&f.device),&request(&f,&f.device,12,112),||112),Err(Error::NoAllowance));
}

#[test]
fn forged_or_expired_request_leaves_no_account_and_nonce_cannot_change_content() {
    let f=Fixture::new();let mut ledger=AllocationLedger::open(":memory:",f.trust.clone(),policy()).unwrap();
    let grant=f.grant(5,&f.device);let mut forged=request(&f,&f.device,10,110);forged.blinded_request=BASE64URL_NOPAD.encode(&[11;384]);
    assert_eq!(ledger.reserve(&grant,&forged,||110),Err(Error::Signature));
    assert_eq!(ledger.balance(&encoded(5)).unwrap(),None);
    let good=request(&f,&f.device,10,110);assert_eq!(ledger.reserve(&grant,&good,||150),Err(Error::Expired));
    ledger.reserve(&grant,&good,||110).unwrap();
    let changed=request(&f,&f.device,10,111);assert_eq!(ledger.reserve(&grant,&changed,||111),Err(Error::Replay));
    assert_eq!(ledger.balance(&encoded(5)).unwrap(),Some(1));
}

#[test]
fn monthly_allowance_cannot_be_reclaimed_on_reconnect_or_clock_rollback() {
    let f=Fixture::new();let dir=tempfile::tempdir().unwrap();let path=dir.path().join("state.sqlite");
    {let mut l=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();l.reserve(&f.grant(5,&f.device),&request(&f,&f.device,10,110),||110).unwrap();l.reserve(&f.grant(5,&f.device),&request(&f,&f.device,11,210),||210).unwrap();assert_eq!(l.balance(&encoded(5)).unwrap(),Some(1));}
    let mut l=AllocationLedger::open(&path,f.trust.clone(),policy()).unwrap();
    assert_eq!(l.reserve(&f.grant(5,&f.device),&request(&f,&f.device,12,110),||110),Err(Error::ClockRollback));
    assert_eq!(l.balance(&encoded(5)).unwrap(),Some(1));
    let mut changed=policy();changed.initial_credits=3;
    assert!(matches!(AllocationLedger::open(&path,f.trust.clone(),changed),Err(Error::PolicyMismatch)));
}

#[test]
fn resolve_answer_or_close_fails_closed_without_proof_backend() {
    let f=Fixture::new();let mut l=AllocationLedger::open(":memory:",f.trust.clone(),policy()).unwrap();
    l.reserve(&f.grant(5,&f.device),&request(&f,&f.device,10,110),||110).unwrap();
    for forged in [b"answered".as_slice(),b"closedForever".as_slice(),b"".as_slice()] {assert_eq!(l.resolve_private(forged),Err(Error::UnsupportedCapability));}
    assert_eq!(l.balance(&encoded(5)).unwrap(),Some(1));
}
