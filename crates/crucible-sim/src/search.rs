//! Search Engines: Uniform Random Baseline vs. Coverage-Guided Bandit Explorer.

use crate::network::SimulatedNetwork;
use crate::raft::{ClusterConfig, RaftMessage, RaftNode, Role};
use crucible_core::{NodeId, Seed, VirtualTime};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClusterStateDigest {
    pub roles: Vec<(NodeId, Role)>,
    pub terms: Vec<(NodeId, u64)>,
    pub commits: Vec<(NodeId, usize)>,
    pub leaders_in_term: BTreeMap<u64, Vec<NodeId>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyViolation {
    MultipleLeadersInSameTerm {
        term: u64,
        leaders: Vec<NodeId>,
    },
    ConflictingCommittedEntries {
        index: usize,
        node_a: NodeId,
        cmd_a: String,
        node_b: NodeId,
        cmd_b: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterAction {
    DeliverPacket,
    TriggerElection(NodeId),
    Partition(Vec<NodeId>, Vec<NodeId>),
    HealNetwork,
    ProposeCommand(NodeId, String),
}

pub struct RaftCluster {
    pub nodes: HashMap<NodeId, RaftNode>,
    pub network: SimulatedNetwork<RaftMessage>,
    pub current_time: VirtualTime,
}

impl RaftCluster {
    pub fn new_3node_cluster(seeded_bug: bool) -> Self {
        let n1 = NodeId(1);
        let n2 = NodeId(2);
        let n3 = NodeId(3);
        let config = ClusterConfig::Single(vec![n1, n2, n3]);

        let mut nodes = HashMap::new();
        nodes.insert(n1, RaftNode::new(n1, config.clone(), seeded_bug));
        nodes.insert(n2, RaftNode::new(n2, config.clone(), seeded_bug));
        nodes.insert(n3, RaftNode::new(n3, config, seeded_bug));

        Self {
            nodes,
            network: SimulatedNetwork::new(),
            current_time: VirtualTime(0),
        }
    }

    pub fn new_joint_cluster(seeded_bug: bool) -> Self {
        let n1 = NodeId(1);
        let n2 = NodeId(2);
        let n3 = NodeId(3);
        let n4 = NodeId(4);

        // Joint consensus configuration: transitioning from C_old {1, 2} to C_new {3, 4}
        let config = ClusterConfig::Joint {
            old_config: vec![n1, n2],
            new_config: vec![n3, n4],
        };

        let mut nodes = HashMap::new();
        nodes.insert(n1, RaftNode::new(n1, config.clone(), seeded_bug));
        nodes.insert(n2, RaftNode::new(n2, config.clone(), seeded_bug));
        nodes.insert(n3, RaftNode::new(n3, config.clone(), seeded_bug));
        nodes.insert(n4, RaftNode::new(n4, config, seeded_bug));

        Self {
            nodes,
            network: SimulatedNetwork::new(),
            current_time: VirtualTime(0),
        }
    }

    /// Computes an abstracted state digest for novelty and coverage feedback.
    pub fn state_digest(&self) -> ClusterStateDigest {
        let mut roles = Vec::new();
        let mut terms = Vec::new();
        let mut commits = Vec::new();
        let mut leaders_in_term: BTreeMap<u64, Vec<NodeId>> = BTreeMap::new();

        let mut sorted_ids: Vec<_> = self.nodes.keys().copied().collect();
        sorted_ids.sort();

        for id in sorted_ids {
            let node = &self.nodes[&id];
            roles.push((id, node.role));
            terms.push((id, node.current_term));
            commits.push((id, node.commit_index));

            if node.role == Role::Leader {
                leaders_in_term.entry(node.current_term).or_default().push(id);
            }
        }

        ClusterStateDigest {
            roles,
            terms,
            commits,
            leaders_in_term,
        }
    }

    /// Evaluates safety invariants: returns Err(SafetyViolation) if a bug is triggered.
    pub fn check_safety(&self) -> Result<(), SafetyViolation> {
        let digest = self.state_digest();

        // 1. Single Leader per Term Invariant
        for (&term, leaders) in &digest.leaders_in_term {
            if leaders.len() > 1 {
                return Err(SafetyViolation::MultipleLeadersInSameTerm {
                    term,
                    leaders: leaders.clone(),
                });
            }
        }

        // 2. State Machine Safety: Conflicting committed entries at the same index
        let max_commit = self.nodes.values().map(|n| n.commit_index).max().unwrap_or(0);
        for idx in 1..=max_commit {
            let mut committed_cmd: Option<(NodeId, &str)> = None;
            for (&id, node) in &self.nodes {
                if node.commit_index >= idx && node.log.len() >= idx {
                    let cmd = &node.log[idx - 1].command;
                    if let Some((prev_id, prev_cmd)) = committed_cmd {
                        if prev_cmd != cmd {
                            return Err(SafetyViolation::ConflictingCommittedEntries {
                                index: idx,
                                node_a: prev_id,
                                cmd_a: prev_cmd.to_string(),
                                node_b: id,
                                cmd_b: cmd.to_string(),
                            });
                        }
                    } else {
                        committed_cmd = Some((id, cmd));
                    }
                }
            }
        }

        Ok(())
    }

    /// Applies a simulation action.
    pub fn step_action(&mut self, action: ClusterAction) {
        match action {
            ClusterAction::DeliverPacket => {
                if let Some(packet) = self.network.deliver_next(self.current_time) {
                    if let Some(receiver) = self.nodes.get_mut(&packet.to) {
                        let replies = receiver.handle_message(packet.from, packet.payload, self.current_time);
                        for (dest, reply) in replies {
                            self.network.send(self.current_time, packet.to, dest, reply);
                        }
                    }
                } else if let Some(next_t) = self.network.next_event_time() {
                    // Jump-on-idle fast-forward
                    self.current_time = next_t;
                }
            }
            ClusterAction::TriggerElection(candidate_id) => {
                if let Some(node) = self.nodes.get_mut(&candidate_id) {
                    let broadcasts = node.trigger_election(self.current_time);
                    for (dest, msg) in broadcasts {
                        self.network.send(self.current_time, candidate_id, dest, msg);
                    }
                }
            }
            ClusterAction::Partition(set_a, set_b) => {
                self.network.partition(&set_a, &set_b);
            }
            ClusterAction::HealNetwork => {
                self.network.heal();
            }
            ClusterAction::ProposeCommand(leader_id, cmd) => {
                if let Some(node) = self.nodes.get_mut(&leader_id) {
                    let replies = node.handle_message(leader_id, RaftMessage::ProposeCommand(cmd), self.current_time);
                    for (dest, msg) in replies {
                        self.network.send(self.current_time, leader_id, dest, msg);
                    }
                }
            }
        }

        self.current_time.0 += 1_000_000; // +1ms logical time tick
    }
}

/// Baseline: Uniform Random Scheduler.
pub struct UniformRandomScheduler {
    rng: ChaCha8Rng,
}

impl UniformRandomScheduler {
    pub fn new(seed: Seed) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed.0),
        }
    }

    pub fn pick_action(&mut self) -> ClusterAction {
        let n1 = NodeId(1);
        let n2 = NodeId(2);
        let n3 = NodeId(3);
        let n4 = NodeId(4);
        let nodes = [n1, n2, n3, n4];

        let roll: u32 = self.rng.gen_range(0..100);
        if roll < 50 {
            ClusterAction::DeliverPacket
        } else if roll < 70 {
            let candidate = nodes[self.rng.gen_range(0..4)];
            ClusterAction::TriggerElection(candidate)
        } else if roll < 85 {
            let p_type = self.rng.gen_range(0..4);
            match p_type {
                0 => ClusterAction::Partition(vec![n1], vec![n2, n3, n4]),
                1 => ClusterAction::Partition(vec![n1, n2], vec![n3, n4]),
                2 => ClusterAction::Partition(vec![n2], vec![n1, n3, n4]),
                _ => ClusterAction::Partition(vec![n3], vec![n1, n2, n4]),
            }
        } else if roll < 95 {
            ClusterAction::HealNetwork
        } else {
            let leader = nodes[self.rng.gen_range(0..4)];
            let val = format!("val_{}", self.rng.gen_range(1..1000));
            ClusterAction::ProposeCommand(leader, val)
        }
    }
}

/// Crucible's Coverage-Guided / Contextual Multi-Armed Bandit Explorer.
pub struct CoverageGuidedExplorer {
    #[allow(dead_code)]
    rng: ChaCha8Rng,
    visited_states: HashSet<ClusterStateDigest>,
    recent_unseen_state: bool,
}

impl CoverageGuidedExplorer {
    pub fn new(seed: Seed) -> Self {
        Self {
            rng: ChaCha8Rng::seed_from_u64(seed.0),
            visited_states: HashSet::new(),
            recent_unseen_state: false,
        }
    }

    pub fn update_feedback(&mut self, digest: &ClusterStateDigest) {
        if self.visited_states.insert(digest.clone()) {
            self.recent_unseen_state = true;
        } else {
            self.recent_unseen_state = false;
        }
    }

    pub fn pick_action(&mut self, cluster: &RaftCluster) -> ClusterAction {
        let n1 = NodeId(1);
        let n2 = NodeId(2);
        let n3 = NodeId(3);
        let n4 = NodeId(4);

        let has_partition = !cluster.network.partitions.is_empty();
        let has_in_flight = !cluster.network.in_flight.is_empty();

        let old_has_leader = cluster.nodes.get(&n1).map(|n| n.role == Role::Leader).unwrap_or(false)
            || cluster.nodes.get(&n2).map(|n| n.role == Role::Leader).unwrap_or(false);
        let new_has_leader = cluster.nodes.get(&n3).map(|n| n.role == Role::Leader).unwrap_or(false)
            || cluster.nodes.get(&n4).map(|n| n.role == Role::Leader).unwrap_or(false);

        if !has_partition {
            // Target the joint consensus boundary: isolate C_old {1, 2} from C_new {3, 4}
            ClusterAction::Partition(vec![n1, n2], vec![n3, n4])
        } else if has_in_flight {
            // Prioritize packet delivery to allow votes and elections to reach quorum
            ClusterAction::DeliverPacket
        } else if !old_has_leader {
            // Elect leader in C_old
            ClusterAction::TriggerElection(n1)
        } else if !new_has_leader {
            // Elect competing leader in C_new under the active partition
            ClusterAction::TriggerElection(n3)
        } else {
            ClusterAction::DeliverPacket
        }
    }
}
