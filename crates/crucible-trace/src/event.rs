//! Canonical trace events and deterministic serialization.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Event classification for deterministic distributed execution traces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventKind {
    InstructionStep = 0,
    SyscallEntry = 1,
    SyscallExit = 2,
    PacketSend = 3,
    PacketRecv = 4,
    FaultInjected = 5,
    StateCheckpoint = 6,
    CheckerAssertion = 7,
    Custom = 8,
}

/// A single discrete event within an execution trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceEvent {
    pub step: u64,
    pub vtime_nanos: u64,
    pub node_id: u32,
    pub thread_id: u64,
    pub kind: EventKind,
    pub payload_digest: String,
    pub summary: String,
}

impl TraceEvent {
    /// Construct a new trace event with a hashed payload digest.
    pub fn new(
        step: u64,
        vtime_nanos: u64,
        node_id: u32,
        thread_id: u64,
        kind: EventKind,
        payload: &[u8],
        summary: impl Into<String>,
    ) -> Self {
        let digest = Sha256::digest(payload);
        let payload_digest = crate::hex_encode(&digest);
        Self {
            step,
            vtime_nanos,
            node_id,
            thread_id,
            kind,
            payload_digest,
            summary: summary.into(),
        }
    }

    /// Computes the deterministic 32-byte hash of this event.
    pub fn compute_leaf_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.step.to_le_bytes());
        hasher.update(self.vtime_nanos.to_le_bytes());
        hasher.update(self.node_id.to_le_bytes());
        hasher.update(self.thread_id.to_le_bytes());
        hasher.update([self.kind as u8]);
        hasher.update(self.payload_digest.as_bytes());
        hasher.update(self.summary.as_bytes());
        let res = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&res);
        out
    }
}
