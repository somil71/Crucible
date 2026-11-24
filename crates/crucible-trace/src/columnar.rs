//! Columnar trace storage for high-throughput deterministic event logging.

use crate::event::{EventKind, TraceEvent};
use crate::merkle::MerkleTree;

/// High-throughput columnar store for execution trace events.
#[derive(Debug, Clone, Default)]
pub struct ColumnarTraceStore {
    steps: Vec<u64>,
    vtimes_nanos: Vec<u64>,
    node_ids: Vec<u32>,
    thread_ids: Vec<u64>,
    kinds: Vec<EventKind>,
    payload_digests: Vec<String>,
    summaries: Vec<String>,
}

impl ColumnarTraceStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            steps: Vec::with_capacity(capacity),
            vtimes_nanos: Vec::with_capacity(capacity),
            node_ids: Vec::with_capacity(capacity),
            thread_ids: Vec::with_capacity(capacity),
            kinds: Vec::with_capacity(capacity),
            payload_digests: Vec::with_capacity(capacity),
            summaries: Vec::with_capacity(capacity),
        }
    }

    pub fn push(&mut self, event: TraceEvent) {
        self.steps.push(event.step);
        self.vtimes_nanos.push(event.vtime_nanos);
        self.node_ids.push(event.node_id);
        self.thread_ids.push(event.thread_id);
        self.kinds.push(event.kind);
        self.payload_digests.push(event.payload_digest);
        self.summaries.push(event.summary);
    }

    pub fn len(&self) -> usize {
        self.steps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Retrieve an event by index.
    pub fn get(&self, index: usize) -> Option<TraceEvent> {
        if index >= self.len() {
            return None;
        }
        Some(TraceEvent {
            step: self.steps[index],
            vtime_nanos: self.vtimes_nanos[index],
            node_id: self.node_ids[index],
            thread_id: self.thread_ids[index],
            kind: self.kinds[index],
            payload_digest: self.payload_digests[index].clone(),
            summary: self.summaries[index].clone(),
        })
    }

    /// Collect all events into a row-oriented vector.
    pub fn to_events(&self) -> Vec<TraceEvent> {
        (0..self.len()).filter_map(|i| self.get(i)).collect()
    }

    /// Build an RFC 6962 Merkle tree over all recorded events.
    pub fn to_merkle_tree(&self) -> MerkleTree {
        let leaf_hashes: Vec<[u8; 32]> = (0..self.len())
            .filter_map(|i| self.get(i).map(|ev| ev.compute_leaf_hash()))
            .collect();
        MerkleTree::from_hashed_leaves(leaf_hashes)
    }
}
