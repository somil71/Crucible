//! RFC 6962-compliant Merkle Transparency Log with domain separation and inclusion proofs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const RFC6962_LEAF_PREFIX: u8 = 0x00;
const RFC6962_NODE_PREFIX: u8 = 0x01;

/// Sibling direction in an inclusion proof audit path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SiblingPosition {
    Left,
    Right,
}

/// A single step in an inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHop {
    pub sibling_hash: String, // hex encoded
    pub position: SiblingPosition,
}

/// Cryptographic Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub tree_size: usize,
    pub leaf_hash: String, // hex encoded
    pub audit_path: Vec<AuditHop>,
}

impl MerkleProof {
    /// Verifies that `leaf_hash` is present at `leaf_index` under `expected_root`.
    pub fn verify(&self, expected_root: &[u8; 32]) -> bool {
        let Ok(leaf_bytes) = crate::hex_decode(&self.leaf_hash) else {
            return false;
        };
        if leaf_bytes.len() != 32 {
            return false;
        }

        let mut current_hash = [0u8; 32];
        current_hash.copy_from_slice(&leaf_bytes);

        for hop in &self.audit_path {
            let Ok(sibling_bytes) = crate::hex_decode(&hop.sibling_hash) else {
                return false;
            };
            if sibling_bytes.len() != 32 {
                return false;
            }

            let mut hasher = Sha256::new();
            hasher.update([RFC6962_NODE_PREFIX]);
            match hop.position {
                SiblingPosition::Left => {
                    hasher.update(&sibling_bytes);
                    hasher.update(&current_hash);
                }
                SiblingPosition::Right => {
                    hasher.update(&current_hash);
                    hasher.update(&sibling_bytes);
                }
            }
            let res = hasher.finalize();
            current_hash.copy_from_slice(&res);
        }

        &current_hash == expected_root
    }
}

/// RFC 6962-compliant Merkle Transparency Log Tree.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    leaf_hashes: Vec<[u8; 32]>,
    root_hash: [u8; 32],
}

impl MerkleTree {
    /// Construct a Merkle tree from raw leaf payload bytes (applying leaf domain prefix).
    pub fn from_raw_leaves(leaves: &[Vec<u8>]) -> Self {
        let hashed_leaves: Vec<[u8; 32]> = leaves
            .iter()
            .map(|leaf| {
                let mut hasher = Sha256::new();
                hasher.update([RFC6962_LEAF_PREFIX]);
                hasher.update(leaf);
                let res = hasher.finalize();
                let mut out = [0u8; 32];
                out.copy_from_slice(&res);
                out
            })
            .collect();

        Self::from_hashed_leaves(hashed_leaves)
    }

    /// Construct a Merkle tree from pre-computed leaf digests (e.g. from TraceEvents).
    pub fn from_hashed_leaves(leaf_hashes: Vec<[u8; 32]>) -> Self {
        let root_hash = compute_mth(&leaf_hashes);
        Self {
            leaf_hashes,
            root_hash,
        }
    }

    pub fn root(&self) -> [u8; 32] {
        self.root_hash
    }

    pub fn root_hex(&self) -> String {
        crate::hex_encode(&self.root_hash)
    }

    pub fn len(&self) -> usize {
        self.leaf_hashes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaf_hashes.is_empty()
    }

    pub fn leaf_hash(&self, index: usize) -> Option<[u8; 32]> {
        self.leaf_hashes.get(index).copied()
    }

    /// Generates an RFC 6962 audit path inclusion proof for the leaf at `leaf_index`.
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        let n = self.leaf_hashes.len();
        if leaf_index >= n {
            return None;
        }

        let mut path = Vec::new();
        build_audit_path(&self.leaf_hashes, leaf_index, &mut path);

        Some(MerkleProof {
            leaf_index,
            tree_size: n,
            leaf_hash: crate::hex_encode(&self.leaf_hashes[leaf_index]),
            audit_path: path,
        })
    }
}

/// Compute largest power of two strictly less than n (k < n <= 2k).
fn largest_power_of_two_less_than(n: usize) -> usize {
    assert!(n > 1);
    let mut k = 1;
    while (k << 1) < n {
        k <<= 1;
    }
    k
}

/// Computes the RFC 6962 Merkle Tree Hash (MTH).
fn compute_mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    let n = leaves.len();
    if n == 0 {
        let empty_hash = Sha256::digest([]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&empty_hash);
        return out;
    }
    if n == 1 {
        return leaves[0];
    }

    let k = largest_power_of_two_less_than(n);
    let left_mth = compute_mth(&leaves[..k]);
    let right_mth = compute_mth(&leaves[k..]);

    let mut hasher = Sha256::new();
    hasher.update([RFC6962_NODE_PREFIX]);
    hasher.update(&left_mth);
    hasher.update(&right_mth);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Recursively builds the audit path according to RFC 6962 §2.1.1.
fn build_audit_path(leaves: &[[u8; 32]], m: usize, path: &mut Vec<AuditHop>) {
    let n = leaves.len();
    if n <= 1 {
        return;
    }

    let k = largest_power_of_two_less_than(n);
    if m < k {
        build_audit_path(&leaves[..k], m, path);
        let sibling = compute_mth(&leaves[k..]);
        path.push(AuditHop {
            sibling_hash: crate::hex_encode(&sibling),
            position: SiblingPosition::Right,
        });
    } else {
        build_audit_path(&leaves[k..], m - k, path);
        let sibling = compute_mth(&leaves[..k]);
        path.push(AuditHop {
            sibling_hash: crate::hex_encode(&sibling),
            position: SiblingPosition::Left,
        });
    }
}
