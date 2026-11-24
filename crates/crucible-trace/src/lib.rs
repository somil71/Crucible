//! Crucible Trace & Evidence Log - Cryptographic attestation and reproducible bundles.

pub mod bundle;
pub mod columnar;
pub mod event;
pub mod merkle;
pub mod verifier;

pub use bundle::{EvidenceBundle, BUNDLE_SCHEMA_VERSION};
pub use columnar::ColumnarTraceStore;
pub use event::{EventKind, TraceEvent};
pub use merkle::{AuditHop, MerkleProof, MerkleTree, SiblingPosition};
pub use verifier::{DeterministicStateReplayer, StandaloneVerifier, TargetReplayer, VerificationReport};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum TraceError {
    #[error("Signature verification failed: invalid signature or corrupt public key")]
    InvalidSignature,
    #[error("Merkle root mismatch: expected {expected}, actual {actual}")]
    MerkleRootMismatch { expected: String, actual: String },
    #[error("State hash mismatch: expected {expected}, actual {actual}")]
    StateHashMismatch { expected: String, actual: String },
    #[error("Replay divergence: expected Merkle root {expected_merkle_root}, actual {actual_merkle_root}")]
    ReplayDivergence {
        expected_merkle_root: String,
        actual_merkle_root: String,
    },
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Replay execution failed: {0}")]
    ReplayError(String),
}

/// Simple hex encoder.
pub fn hex_encode(data: impl AsRef<[u8]>) -> String {
    data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}

/// Simple hex decoder.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, TraceError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(TraceError::Serialization(
            "Odd length hex string".to_string(),
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| TraceError::Serialization(format!("Invalid hex char: {e}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn test_evidence_bundle_lifecycle_and_tamper_detection() {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);

        let mut events = Vec::new();
        for i in 0..10 {
            events.push(TraceEvent::new(
                i,
                i * 1000,
                1,
                1,
                EventKind::InstructionStep,
                format!("step_{i}").as_bytes(),
                format!("instruction step {i}"),
            ));
        }

        let bundle = EvidenceBundle::create_attested(
            "bundle-001",
            "2026-11-24T12:00:00Z",
            "TierA",
            "raft_consensus",
            "sha256:container_abc123",
            "git:commit:fedcba",
            42,
            r#"{"injected_faults": []}"#,
            events,
            "state_hash_0x12345678",
            &signing_key,
        );

        // Verification must pass
        assert!(bundle.verify_all().is_ok());

        // Merkle proof generation and verification
        let leaf_hashes: Vec<[u8; 32]> = bundle.events.iter().map(|e| e.compute_leaf_hash()).collect();
        let tree = MerkleTree::from_hashed_leaves(leaf_hashes);
        let proof = tree.generate_proof(3).expect("proof for leaf 3");
        assert!(proof.verify(&tree.root()));

        // Tamper test: seed change
        let mut tampered_seed = bundle.clone();
        tampered_seed.seed = 999;
        assert!(tampered_seed.verify_signature().is_err());

        // Tamper test: event payload change
        let mut tampered_event = bundle.clone();
        tampered_event.events[0].summary = "corrupted".into();
        assert!(tampered_event.verify_merkle_integrity().is_err());

        // StandaloneVerifier test
        let report = StandaloneVerifier::verify_static(&bundle).expect("report");
        assert!(report.signature_valid);
        assert!(report.merkle_root_valid);
    }
}
