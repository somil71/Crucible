//! Vector Clocks and Happens-Before Causal Graph Analysis.
//!
//! Tracks logical causal dependencies across distributed nodes, performs
//! transitive causal reduction, extracts causal slices leading to invariant
//! violations, and detects concurrency races.

use crucible_core::{NodeId, VirtualTime};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Vector Clock representing causal logical time across distributed actors.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VectorClock {
    pub clock: BTreeMap<NodeId, u64>,
}

impl VectorClock {
    pub fn new() -> Self {
        Self {
            clock: BTreeMap::new(),
        }
    }

    /// Increments this node's own logical component.
    pub fn tick(&mut self, node: NodeId) {
        let entry = self.clock.entry(node).or_insert(0);
        *entry += 1;
    }

    /// Merges an incoming vector clock by taking pairwise maximums.
    pub fn merge(&mut self, other: &VectorClock) {
        for (&node, &val) in &other.clock {
            let entry = self.clock.entry(node).or_insert(0);
            *entry = (*entry).max(val);
        }
    }

    /// Evaluates if `self` causally happens-before `other` (self -> other).
    /// True iff for all k, self[k] <= other[k] AND exists k where self[k] < other[k].
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        let mut strictly_less = false;

        // Check all keys in self
        for (&node, &val) in &self.clock {
            let other_val = other.clock.get(&node).copied().unwrap_or(0);
            if val > other_val {
                return false;
            }
            if val < other_val {
                strictly_less = true;
            }
        }

        // Check if other has keys not in self that are > 0
        for (&node, &val) in &other.clock {
            if !self.clock.contains_key(&node) && val > 0 {
                strictly_less = true;
            }
        }

        strictly_less
    }

    /// Returns true if self and other are causally concurrent (neither happens before the other).
    pub fn is_concurrent_with(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self) && self != other
    }
}

/// A recorded event stamped with its vector clock and virtual time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalEvent {
    pub id: u64,
    pub node: NodeId,
    pub vclock: VectorClock,
    pub description: String,
    pub vtime: VirtualTime,
}

/// Directed Causal Graph tracking distributed message and state causality.
#[derive(Debug, Clone, Default)]
pub struct CausalGraph {
    pub events: Vec<CausalEvent>,
}

impl CausalGraph {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn record_event(
        &mut self,
        node: NodeId,
        vclock: &VectorClock,
        description: impl Into<String>,
        vtime: VirtualTime,
    ) -> u64 {
        let id = self.events.len() as u64 + 1;
        self.events.push(CausalEvent {
            id,
            node,
            vclock: vclock.clone(),
            description: description.into(),
            vtime,
        });
        id
    }

    /// Extracts the minimal causal backward slice for a target event (e.g. an invariant violation).
    /// Discards all concurrent and downstream events that did NOT causally influence target.
    pub fn causal_slice(&self, target_event_id: u64) -> Vec<CausalEvent> {
        let target_event = match self.events.iter().find(|e| e.id == target_event_id) {
            Some(e) => e,
            None => return Vec::new(),
        };

        self.events
            .iter()
            .filter(|e| e.id == target_event.id || e.vclock.happens_before(&target_event.vclock))
            .cloned()
            .collect()
    }

    /// Finds all pairs of events in the execution that are causally concurrent.
    pub fn find_concurrent_pairs(&self) -> Vec<(u64, u64)> {
        let mut concurrent = Vec::new();
        let n = self.events.len();

        for i in 0..n {
            for j in (i + 1)..n {
                let e1 = &self.events[i];
                let e2 = &self.events[j];
                if e1.vclock.is_concurrent_with(&e2.vclock) {
                    concurrent.push((e1.id, e2.id));
                }
            }
        }

        concurrent
    }

    /// Verifies causal monotonicity: no message receive event has a vclock that
    /// violates happens-before of its corresponding send event.
    pub fn verify_causal_monotonicity(&self) -> Result<(), String> {
        let mut last_node_clock: BTreeMap<NodeId, VectorClock> = BTreeMap::new();

        for event in &self.events {
            if let Some(prev) = last_node_clock.get(&event.node) {
                if !prev.happens_before(&event.vclock) {
                    return Err(format!(
                        "Causal clock inversion detected on node {:?}: event {} did not advance logical time",
                        event.node, event.id
                    ));
                }
            }
            last_node_clock.insert(event.node, event.vclock.clone());
        }

        Ok(())
    }
}

/// Minimal causal explanation DAG for an observed violation event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CausalExplanation {
    pub target_event_id: u64,
    pub critical_events: Vec<CausalEvent>,
    pub direct_causal_edges: Vec<(u64, u64)>,
    pub pruned_events_count: usize,
    pub noise_reduction_ratio: f64,
}

/// Causal Trace Slicer and Minimal Hasse Diagram Generator.
pub struct CausalTraceSlicer;

impl CausalTraceSlicer {
    /// Extracts an irreducibly minimal causal explanation DAG for a target failure event.
    /// Prunes all concurrent noise and downstream operations, computing the transitive reduction.
    pub fn slice_and_explain(graph: &CausalGraph, target_event_id: u64) -> Option<CausalExplanation> {
        let total_events = graph.events.len();
        let target_event = graph.events.iter().find(|e| e.id == target_event_id)?;

        // 1. Backward causal cone extraction
        let mut critical_events: Vec<CausalEvent> = graph
            .events
            .iter()
            .filter(|e| e.id == target_event.id || e.vclock.happens_before(&target_event.vclock))
            .cloned()
            .collect();

        // Sort in causal topological order
        critical_events.sort_by(|a, b| {
            if a.vclock.happens_before(&b.vclock) {
                std::cmp::Ordering::Less
            } else if b.vclock.happens_before(&a.vclock) {
                std::cmp::Ordering::Greater
            } else {
                a.id.cmp(&b.id)
            }
        });

        // 2. Transitive Reduction: find direct causal dependencies a -> b
        let mut direct_edges = Vec::new();
        let m = critical_events.len();

        for i in 0..m {
            for j in 0..m {
                if i != j && critical_events[i].vclock.happens_before(&critical_events[j].vclock) {
                    let mut has_intermediate = false;
                    for k in 0..m {
                        if k != i
                            && k != j
                            && critical_events[i].vclock.happens_before(&critical_events[k].vclock)
                            && critical_events[k].vclock.happens_before(&critical_events[j].vclock)
                        {
                            has_intermediate = true;
                            break;
                        }
                    }

                    if !has_intermediate {
                        direct_edges.push((critical_events[i].id, critical_events[j].id));
                    }
                }
            }
        }

        let pruned_count = total_events.saturating_sub(critical_events.len());
        let noise_reduction_ratio = if total_events > 0 {
            pruned_count as f64 / total_events as f64
        } else {
            0.0
        };

        Some(CausalExplanation {
            target_event_id,
            critical_events,
            direct_causal_edges: direct_edges,
            pruned_events_count: pruned_count,
            noise_reduction_ratio,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_clock_causality() {
        let n1 = NodeId(1);
        let n2 = NodeId(2);

        let mut vc1 = VectorClock::new();
        vc1.tick(n1); // vc1: {1: 1}

        let mut vc2 = VectorClock::new();
        vc2.tick(n2); // vc2: {2: 1}

        // Concurrent events
        assert!(vc1.is_concurrent_with(&vc2));
        assert!(!vc1.happens_before(&vc2));
        assert!(!vc2.happens_before(&vc1));

        // Message passing: Node 2 receives from Node 1
        vc2.merge(&vc1);
        vc2.tick(n2); // vc2: {1: 1, 2: 2}

        // vc1 strictly happens-before vc2
        assert!(vc1.happens_before(&vc2));
        assert!(!vc2.happens_before(&vc1));
        assert!(!vc1.is_concurrent_with(&vc2));
    }

    #[test]
    fn test_causal_graph_slicing() {
        let mut graph = CausalGraph::new();
        let n1 = NodeId(1);
        let n2 = NodeId(2);
        let n3 = NodeId(3);

        let mut vc1 = VectorClock::new();
        let mut vc2 = VectorClock::new();
        let mut vc3 = VectorClock::new();

        // 1. Node 1 local step
        vc1.tick(n1);
        let e1 = graph.record_event(n1, &vc1, "Node 1 Init", VirtualTime(10));

        // 2. Node 2 local step (concurrent with e1)
        vc2.tick(n2);
        let e2 = graph.record_event(n2, &vc2, "Node 2 Unrelated Action", VirtualTime(15));

        // 3. Node 3 receives from Node 1
        vc3.merge(&vc1);
        vc3.tick(n3);
        let e3 = graph.record_event(n3, &vc3, "Node 3 Receives N1", VirtualTime(20));

        // 4. Node 3 triggers failure
        vc3.tick(n3);
        let e4_fail = graph.record_event(n3, &vc3, "Node 3 Crash / Failure", VirtualTime(25));

        // Causal slice for e4_fail should contain: e1, e3, e4_fail.
        // It must NOT contain e2 (which was on Node 2 and causally unrelated)!
        let slice = graph.causal_slice(e4_fail);
        let slice_ids: Vec<u64> = slice.iter().map(|e| e.id).collect();

        assert_eq!(slice_ids, vec![e1, e3, e4_fail]);
        assert!(!slice_ids.contains(&e2));
    }

    #[test]
    fn test_causal_trace_slicer_transitive_reduction() {
        let mut graph = CausalGraph::new();
        let n1 = NodeId(1);

        let mut vc = VectorClock::new();
        vc.tick(n1);
        let e1 = graph.record_event(n1, &vc, "Step 1", VirtualTime(10));

        vc.tick(n1);
        let e2 = graph.record_event(n1, &vc, "Step 2", VirtualTime(20));

        vc.tick(n1);
        let e3 = graph.record_event(n1, &vc, "Step 3 (Target)", VirtualTime(30));

        // Transitive: e1 -> e2 -> e3. Direct edges should ONLY be (e1, e2) and (e2, e3).
        // The redundant transitive edge (e1, e3) should be reduced away.
        let explanation = CausalTraceSlicer::slice_and_explain(&graph, e3).unwrap();
        assert_eq!(explanation.critical_events.len(), 3);
        assert_eq!(explanation.direct_causal_edges, vec![(e1, e2), (e2, e3)]);
    }
}
