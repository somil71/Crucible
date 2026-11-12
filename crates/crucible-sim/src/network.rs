//! Deterministic Simulated Network with Partition, Delay, and Loss Models.

use crucible_core::{EventQueue, NodeId, VirtualTime};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPacket<M: Clone + Eq> {
    pub from: NodeId,
    pub to: NodeId,
    pub payload: M,
    pub sent_at: VirtualTime,
}

pub struct SimulatedNetwork<M: Clone + Eq> {
    pub in_flight: EventQueue<NetworkPacket<M>>,
    pub partitions: HashSet<(NodeId, NodeId)>,
    pub drop_rate: f64,
    pub default_latency_nanos: u64,
}

impl<M: Clone + Eq> Default for SimulatedNetwork<M> {
    fn default() -> Self {
        Self {
            in_flight: EventQueue::new(),
            partitions: HashSet::new(),
            drop_rate: 0.0,
            default_latency_nanos: 1_000_000, // 1ms
        }
    }
}

impl<M: Clone + Eq> SimulatedNetwork<M> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Isolates two sets of nodes from communicating with each other (symmetric partition).
    pub fn partition(&mut self, set_a: &[NodeId], set_b: &[NodeId]) {
        for &a in set_a {
            for &b in set_b {
                self.partitions.insert((a, b));
                self.partitions.insert((b, a));
            }
        }
    }

    /// Sets up an asymmetric (directed) partition where packets from `from_nodes`
    /// cannot reach `to_nodes`, but the reverse direction may still function.
    pub fn partition_directed(&mut self, from_nodes: &[NodeId], to_nodes: &[NodeId]) {
        for &a in from_nodes {
            for &b in to_nodes {
                self.partitions.insert((a, b));
            }
        }
    }

    /// Restores full connectivity across all nodes.
    pub fn heal(&mut self) {
        self.partitions.clear();
    }

    /// Returns true if a packet from `src` to `dst` is currently blocked by a network partition.
    pub fn is_blocked(&self, from: NodeId, to: NodeId) -> bool {
        self.partitions.contains(&(from, to))
    }

    /// Sends a packet with virtual latency if not partitioned.
    pub fn send(&mut self, current_time: VirtualTime, from: NodeId, to: NodeId, payload: M) -> bool {
        if self.is_blocked(from, to) {
            return false;
        }

        let arrival_time = VirtualTime(current_time.0 + self.default_latency_nanos);
        self.in_flight.schedule(
            arrival_time,
            NetworkPacket {
                from,
                to,
                payload,
                sent_at: current_time,
            },
        );
        true
    }

    /// Pops the next packet ready for delivery at or before `current_time`.
    pub fn deliver_next(&mut self, current_time: VirtualTime) -> Option<NetworkPacket<M>> {
        if let Some(next_time) = self.in_flight.peek_time() {
            if next_time <= current_time {
                let event = self.in_flight.pop_next().unwrap();
                if self.is_blocked(event.payload.from, event.payload.to) {
                    // Dropped due to partition established after dispatch
                    return None;
                }
                return Some(event.payload);
            }
        }
        None
    }

    /// Fast-forwards to next packet delivery timestamp (jump-on-idle).
    pub fn next_event_time(&self) -> Option<VirtualTime> {
        self.in_flight.peek_time()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_partition_and_heal() {
        let mut net = SimulatedNetwork::<String>::new();
        let n1 = NodeId(1);
        let n2 = NodeId(2);

        net.partition(&[n1], &[n2]);
        assert!(net.is_blocked(n1, n2));
        assert!(net.is_blocked(n2, n1));

        assert!(!net.send(VirtualTime(0), n1, n2, "hello".into()));

        net.heal();
        assert!(!net.is_blocked(n1, n2));
        assert!(net.send(VirtualTime(0), n1, n2, "hello".into()));
    }

    #[test]
    fn test_network_asymmetric_partition() {
        let mut net = SimulatedNetwork::<String>::new();
        let n1 = NodeId(1);
        let n2 = NodeId(2);

        // Asymmetric partition: N1 cannot reach N2, but N2 CAN reach N1
        net.partition_directed(&[n1], &[n2]);
        assert!(net.is_blocked(n1, n2));
        assert!(!net.is_blocked(n2, n1));

        assert!(!net.send(VirtualTime(0), n1, n2, "ping".into()));
        assert!(net.send(VirtualTime(0), n2, n1, "pong".into()));
    }
}
