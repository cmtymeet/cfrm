//! Isolated account-proof/SQLite integration fixture. Synthetic operator key;
//! never a deployed service. Only the configured local verifier can approve a
//! fresh statement. Public browser inputs cannot select commands, paths or VKs.

use cfrm::{
    accounting::*,
    accounting_ledger::*,
    admission::{AdmissionGrant, AdmissionTrust, DeviceAuthorization},
    Error,
};
use data_encoding::HEXLOWER;
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    community_id: String,
    admission_policy_digest: String,
    issuer_public_key: [u8; 32],
    policy: AccountLedgerPolicy,
    proof_scope: AccountProofScope,
    checkpoints: Vec<Checkpoint>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Checkpoint {
    slot: u64,
    root: [u8; 32],
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase", deny_unknown_fields)]
enum Input {
    Prepare {
        request: AccountRequest,
    },
    Verify {
        statement: AccountStatement,
        proof: Vec<u8>,
    },
    Apply {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountRequest,
        now: u64,
    },
    Status {
        grant: AdmissionGrant,
        authorization: DeviceAuthorization,
        request: AccountStatusRequest,
        now: u64,
    },
}

struct RealProcessVerifier {
    scope: AccountProofScope,
    script: PathBuf,
    manifest: PathBuf,
    enrollment: PathBuf,
}
impl AccountProofVerifier for RealProcessVerifier {
    fn scope(&self) -> AccountProofScope {
        self.scope.clone()
    }
    fn verify(&self, statement: &AccountStatement, proof: &[u8]) -> Result<(), Error> {
        let bytes = serde_json::to_vec(&json!({ "statement": statement,
            "proof": HEXLOWER.encode(proof), "proofScope": self.scope }))
        .map_err(|_| Error::CryptoProvider)?;
        // GNU timeout is a declared test-runner dependency. No shell or browser
        // field is interpreted as executable text. The process has only public
        // inputs; witness openings remain in the browser.
        let mut child = Command::new("timeout")
            .args(["--foreground", "--kill-after=5", "120", "node"])
            .arg(&self.script)
            .arg(&self.manifest)
            .arg(&self.enrollment)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| Error::CryptoProvider)?;
        child
            .stdin
            .take()
            .ok_or(Error::CryptoProvider)?
            .write_all(&bytes)
            .map_err(|_| Error::CryptoProvider)?;
        let output = child
            .wait_with_output()
            .map_err(|_| Error::CryptoProvider)?;
        if !output.status.success() || output.stdout.len() > 4096 {
            return Err(Error::CryptoProvider);
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Verdict {
            verified: bool,
            proof_scope: AccountProofScope,
        }
        let verdict: Verdict =
            serde_json::from_slice(&output.stdout).map_err(|_| Error::CryptoProvider)?;
        if !verdict.verified || verdict.proof_scope != self.scope {
            return Err(Error::CryptoProvider);
        }
        Ok(())
    }
}

fn run() -> Result<Value, Box<dyn std::error::Error>> {
    // All CLI paths are supplied by the trusted CI harness, never browser IPC.
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 7 && args.len() != 8 {
        return Err(
            "config database verifier manifest enrollment mode [drop-response] required".into(),
        );
    }
    if args[6] != "account-state-v2" || (args.len() == 8 && args[7] != "drop-response") {
        return Err("invalid fixture mode".into());
    }
    let config: Config = serde_json::from_slice(&std::fs::read(&args[1])?)?;
    let manifest: Value = serde_json::from_slice(&std::fs::read(&args[4])?)?;
    if manifest["accountingMode"] != "account-state-v2"
        || manifest["circuitSha256"] != HEXLOWER.encode(&config.proof_scope.circuit_digest)
        || manifest["vkSha256"] != HEXLOWER.encode(&config.proof_scope.verifying_key_digest)
    {
        return Err("trusted artifact scope mismatch".into());
    }
    let mut input = Vec::new();
    std::io::stdin().take(2_000_001).read_to_end(&mut input)?;
    if input.len() > 2_000_000 {
        return Err("fixture input bound".into());
    }
    let command: Input = serde_json::from_slice(&input)?;
    if let Input::Prepare { request } = command {
        return Ok(json!({ "request": request,
            "statementDigest": HEXLOWER.encode(&Sha256::digest(statement_bytes(&request.statement)?)),
            "proofDigest": HEXLOWER.encode(&Sha256::digest(&request.proof)),
            "signingBytes": HEXLOWER.encode(&account_request_bytes(&request)?) }));
    }
    let verifier = RealProcessVerifier {
        scope: config.proof_scope,
        script: std::fs::canonicalize(&args[3])?,
        manifest: std::fs::canonicalize(&args[4])?,
        enrollment: std::fs::canonicalize(&args[5])?,
    };
    if let Input::Verify { statement, proof } = command {
        verifier.verify(&statement, &proof)?;
        return Ok(json!({ "verified": true }));
    }
    let trust = AdmissionTrust {
        community_id: config.community_id,
        policy_digest: config.admission_policy_digest,
        issuer_public_key: config.issuer_public_key,
    };
    let mut ledger = AccountLedger::open(
        &args[2],
        trust,
        config.policy,
        verifier,
        SigningKey::from_bytes(&[0x4c; 32]),
    )?;
    for checkpoint in config.checkpoints {
        ledger.admit_checkpoint(checkpoint.slot, checkpoint.root)?;
    }
    let result = match command {
        Input::Apply {
            grant,
            authorization,
            request,
            now,
        } => serde_json::to_value(ledger.apply(&grant, &authorization, &request, || now)?),
        Input::Status {
            grant,
            authorization,
            request,
            now,
        } => serde_json::to_value(ledger.status(&grant, &authorization, &request, || now)?),
        Input::Prepare { .. } | Input::Verify { .. } => unreachable!(),
    }?;
    if args.len() == 8 {
        std::process::exit(0);
    } // Commit survived; response deliberately lost.
    Ok(result)
}

fn main() {
    match run() {
        Ok(result) => println!("{}", json!({ "ok": true, "value": result })),
        Err(error) => {
            println!("{}", json!({ "ok": false, "error": error.to_string() }));
            std::process::exit(1);
        }
    }
}
