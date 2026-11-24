//! Cryptographically signed evidence bundle with Merkle audit support.

use crate::event::TraceEvent;
use crate::merkle::MerkleTree;
use crate::TraceError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const BUNDLE_SCHEMA_VERSION: &str = "1.0.0";

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

    // Extended attestation fields
    #[serde(default = "default_schema_version")]
    pub schema_version: String,
    #[serde(default)]
    pub bundle_id: String,
    #[serde(default)]
    pub created_at_utc: String,
    #[serde(default)]
    pub tier: String,
    #[serde(default)]
    pub target_name: String,
    #[serde(default)]
    pub total_events: usize,
    #[serde(default)]
    pub merkle_root: String,
    #[serde(default)]
    pub final_state_hash: String,
    #[serde(default)]
    pub events: Vec<TraceEvent>,
}

fn default_schema_version() -> String {
    BUNDLE_SCHEMA_VERSION.to_string()
}

impl EvidenceBundle {
    /// Create standard evidence bundle from raw execution trace data.
    pub fn create(
        seed: u64,
        container_digest: String,
        binary_build_hash: String,
        fault_schedule_json: String,
        trace_data: &[u8],
        signing_key: &SigningKey,
    ) -> Self {
        let trace_hash = crate::hex_encode(Sha256::digest(trace_data));
        let digest = compute_standard_digest(
            seed,
            &container_digest,
            &binary_build_hash,
            &fault_schedule_json,
            &trace_hash,
        );

        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();

        Self {
            seed,
            container_digest,
            binary_build_hash,
            fault_schedule_json,
            trace_hash: trace_hash.clone(),
            public_key_bytes: verifying_key.to_bytes().to_vec(),
            signature_bytes: signature.to_bytes().to_vec(),
            schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id: format!("bundle-{seed:016x}"),
            created_at_utc: "2026-11-24T12:00:00Z".to_string(),
            tier: "TierC".to_string(),
            target_name: "workload".to_string(),
            total_events: 0,
            merkle_root: trace_hash,
            final_state_hash: String::new(),
            events: Vec::new(),
        }
    }

    /// Create rich evidence bundle with Merkle transparency tree and discrete events.
    pub fn create_attested(
        bundle_id: impl Into<String>,
        created_at_utc: impl Into<String>,
        tier: impl Into<String>,
        target_name: impl Into<String>,
        container_digest: impl Into<String>,
        binary_build_hash: impl Into<String>,
        seed: u64,
        fault_schedule_json: impl Into<String>,
        events: Vec<TraceEvent>,
        final_state_hash: impl Into<String>,
        signing_key: &SigningKey,
    ) -> Self {
        let bundle_id = bundle_id.into();
        let created_at_utc = created_at_utc.into();
        let tier = tier.into();
        let target_name = target_name.into();
        let container_digest = container_digest.into();
        let binary_build_hash = binary_build_hash.into();
        let fault_schedule_json = fault_schedule_json.into();
        let final_state_hash = final_state_hash.into();

        let leaf_hashes: Vec<[u8; 32]> = events.iter().map(|e| e.compute_leaf_hash()).collect();
        let merkle_tree = MerkleTree::from_hashed_leaves(leaf_hashes);
        let merkle_root = merkle_tree.root_hex();
        let total_events = events.len();

        let digest = compute_standard_digest(
            seed,
            &container_digest,
            &binary_build_hash,
            &fault_schedule_json,
            &merkle_root,
        );

        let signature = signing_key.sign(&digest);
        let verifying_key = signing_key.verifying_key();

        Self {
            seed,
            container_digest,
            binary_build_hash,
            fault_schedule_json,
            trace_hash: merkle_root.clone(),
            public_key_bytes: verifying_key.to_bytes().to_vec(),
            signature_bytes: signature.to_bytes().to_vec(),
            schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
            bundle_id,
            created_at_utc,
            tier,
            target_name,
            total_events,
            merkle_root,
            final_state_hash,
            events,
        }
    }

    /// Verify signature.
    pub fn verify(&self) -> Result<(), TraceError> {
        self.verify_signature()
    }

    /// Verifies cryptographic signature.
    pub fn verify_signature(&self) -> Result<(), TraceError> {
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

        let digest = compute_standard_digest(
            self.seed,
            &self.container_digest,
            &self.binary_build_hash,
            &self.fault_schedule_json,
            &self.trace_hash,
        );

        verifying_key
            .verify(&digest, &signature)
            .map_err(|_| TraceError::InvalidSignature)
    }

    /// Re-constructs the Merkle tree from all recorded events and asserts root match.
    pub fn verify_merkle_integrity(&self) -> Result<(), TraceError> {
        if self.events.is_empty() {
            return Ok(());
        }

        let leaf_hashes: Vec<[u8; 32]> = self.events.iter().map(|e| e.compute_leaf_hash()).collect();
        let tree = MerkleTree::from_hashed_leaves(leaf_hashes);
        let calculated_root = tree.root_hex();

        if calculated_root != self.merkle_root {
            return Err(TraceError::MerkleRootMismatch {
                expected: self.merkle_root.clone(),
                actual: calculated_root,
            });
        }
        Ok(())
    }

    /// Runs all static cryptographic and integrity checks.
    pub fn verify_all(&self) -> Result<(), TraceError> {
        self.verify_signature()?;
        self.verify_merkle_integrity()?;
        Ok(())
    }

    pub fn public_key_hex(&self) -> String {
        crate::hex_encode(&self.public_key_bytes)
    }

    pub fn signature_hex(&self) -> String {
        crate::hex_encode(&self.signature_bytes)
    }

    /// Serializes bundle to formatted JSON string.
    pub fn to_json(&self) -> Result<String, TraceError> {
        serde_json::to_string_pretty(self).map_err(|e| TraceError::Serialization(e.to_string()))
    }

    /// Deserializes bundle from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, TraceError> {
        serde_json::from_str(json_str).map_err(|e| TraceError::Serialization(e.to_string()))
    }

    /// Saves bundle to disk.
    pub fn save_to_file(&self, path: impl AsRef<Path>) -> Result<(), TraceError> {
        let json = self.to_json()?;
        std::fs::write(path, json).map_err(|e| TraceError::Io(e.to_string()))
    }

    /// Loads bundle from disk.
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self, TraceError> {
        let text = std::fs::read_to_string(path).map_err(|e| TraceError::Io(e.to_string()))?;
        Self::from_json(&text)
    }
}

fn compute_standard_digest(
    seed: u64,
    container_digest: &str,
    binary_build_hash: &str,
    fault_schedule_json: &str,
    trace_hash: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.to_le_bytes());
    hasher.update(container_digest.as_bytes());
    hasher.update(binary_build_hash.as_bytes());
    hasher.update(fault_schedule_json.as_bytes());
    hasher.update(trace_hash.as_bytes());
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}
