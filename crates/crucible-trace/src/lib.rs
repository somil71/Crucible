//! Crucible Trace & Evidence Log - Cryptographic attestation and reproducible bundles.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("Signature verification failed")]
    InvalidSignature,
    #[error("Trace hash mismatch: expected {expected}, actual {actual}")]
    HashMismatch { expected: String, actual: String },
}

/// Standalone cryptographic evidence bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub seed: u64,
    pub container_digest: String,
    pub binary_build_hash: String,
    pub fault_schedule_json: String,
    pub trace_hash: String,
    pub public_key_bytes: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

impl EvidenceBundle {
    pub fn create(
        seed: u64,
        container_digest: String,
        binary_build_hash: String,
        fault_schedule_json: String,
        trace_data: &[u8],
        signing_key: &SigningKey,
    ) -> Self {
        let trace_hash = hex::encode(Sha256::digest(trace_data));
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(seed.to_le_bytes());
        msg_hasher.update(container_digest.as_bytes());
        msg_hasher.update(binary_build_hash.as_bytes());
        msg_hasher.update(fault_schedule_json.as_bytes());
        msg_hasher.update(trace_hash.as_bytes());
        let digest = msg_hasher.finalize();

        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();

        Self {
            seed,
            container_digest,
            binary_build_hash,
            fault_schedule_json,
            trace_hash,
            public_key_bytes: verifying_key.to_bytes().to_vec(),
            signature_bytes: signature.to_bytes().to_vec(),
        }
    }

    pub fn verify(&self) -> Result<(), TraceError> {
        if self.public_key_bytes.len() != 32 || self.signature_bytes.len() != 64 {
            return Err(TraceError::InvalidSignature);
        }

        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&self.public_key_bytes);
        let verifying_key =
            VerifyingKey::from_bytes(&pk_arr).map_err(|_| TraceError::InvalidSignature)?;

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let mut msg_hasher = Sha256::new();
        msg_hasher.update(self.seed.to_le_bytes());
        msg_hasher.update(self.container_digest.as_bytes());
        msg_hasher.update(self.binary_build_hash.as_bytes());
        msg_hasher.update(self.fault_schedule_json.as_bytes());
        msg_hasher.update(self.trace_hash.as_bytes());
        let digest = msg_hasher.finalize();

        verifying_key
            .verify(&digest, &signature)
            .map_err(|_| TraceError::InvalidSignature)
    }
}

// Simple hex encoding helper for no-std/minimal dependencies
mod hex {
    pub fn encode(data: impl AsRef<[u8]>) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_evidence_bundle_signature_verification() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let bundle = EvidenceBundle::create(
            42,
            "sha256:abc1234".into(),
            "git:commit:fedcba".into(),
            "[]".into(),
            b"execution trace binary bytes",
            &signing_key,
        );

        assert!(bundle.verify().is_ok());

        // Tamper test
        let mut tampered = bundle.clone();
        tampered.seed = 43;
        assert!(tampered.verify().is_err());
    }
}
