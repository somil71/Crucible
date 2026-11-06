//! Crucible Core - Deterministic world primitives, logical clock, and fault model.

pub mod scheduler;
pub use scheduler::*;

pub mod minimizer;
pub use minimizer::*;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BinaryHeap;
use std::cmp::Ordering;

/// Seed used to initialize the deterministic pseudo-random generator and schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Seed(pub u64);

/// Logical Virtual Time in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct VirtualTime(pub u64);

impl VirtualTime {
    pub const ZERO: Self = Self(0);

    pub fn from_millis(ms: u64) -> Self {
        Self(ms * 1_000_000)
    }

    pub fn as_millis(&self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn advance_by(&mut self, nanos: u64) {
        self.0 += nanos;
    }
}

/// Unique identifier for an emulated or simulated thread/task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ThreadId(pub u32);

/// Unique identifier for a simulated cluster node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeId(pub u32);

/// Scheduled timed event in the deterministic event queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimedEvent<T> {
    pub scheduled_at: VirtualTime,
    pub sequence: u64,
    pub payload: T,
}

impl<T: Eq> Ord for TimedEvent<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering so BinaryHeap acts as a min-heap
        other
            .scheduled_at
            .cmp(&self.scheduled_at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl<T: Eq> PartialOrd for TimedEvent<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Priority queue of timed events ensuring jump-on-idle determinism.
#[derive(Default)]
pub struct EventQueue<T: Eq> {
    heap: BinaryHeap<TimedEvent<T>>,
    seq_counter: u64,
}

impl<T: Eq> EventQueue<T> {
    pub fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
            seq_counter: 0,
        }
    }

    pub fn schedule(&mut self, at: VirtualTime, payload: T) {
        let seq = self.seq_counter;
        self.seq_counter += 1;
        self.heap.push(TimedEvent {
            scheduled_at: at,
            sequence: seq,
            payload,
        });
    }

    pub fn peek_time(&self) -> Option<VirtualTime> {
        self.heap.peek().map(|e| e.scheduled_at)
    }

    pub fn pop_next(&mut self) -> Option<TimedEvent<T>> {
        self.heap.pop()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }
}

/// Fault Injection Schedule DSL Program.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FaultAction {
    NetworkPartition {
        partition_a: Vec<NodeId>,
        partition_b: Vec<NodeId>,
    },
    NetworkHeal,
    PacketLoss {
        rate: f64,
    },
    DelayPacket {
        from: NodeId,
        to: NodeId,
        delay_nanos: u64,
    },
    CrashNode {
        node: NodeId,
    },
    RestartNode {
        node: NodeId,
        retain_disk: bool,
    },
    TornWriteDisk {
        node: NodeId,
        sector: u64,
    },
    ClockSkew {
        node: NodeId,
        offset_nanos: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduledFault {
    pub trigger_time: VirtualTime,
    pub action: FaultAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FaultSchedule {
    pub seed: u64,
    pub faults: Vec<ScheduledFault>,
}

/// Cryptographic state trace hash.
pub fn compute_trace_hash(events: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(events);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_queue_min_heap_order() {
        let mut q = EventQueue::new();
        q.schedule(VirtualTime(200), "event2");
        q.schedule(VirtualTime(100), "event1");
        q.schedule(VirtualTime(100), "event1_b"); // sequence break

        assert_eq!(q.pop_next().unwrap().payload, "event1");
        assert_eq!(q.pop_next().unwrap().payload, "event1_b");
        assert_eq!(q.pop_next().unwrap().payload, "event2");
    }

    #[test]
    fn test_trace_hash_reproducibility() {
        let trace1 = b"event:thread1:step1;event:thread2:step2";
        let trace2 = b"event:thread1:step1;event:thread2:step2";
        assert_eq!(compute_trace_hash(trace1), compute_trace_hash(trace2));
    }
}
