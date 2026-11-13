//! Historical Raft Figure 8 Commit Bug Target.
//!
//! Models the historical consensus anomaly documented in Raft §5.4.2 (and observed
//! in early distributed consensus engines like tikv/raft-rs and openraft issues):
//! A leader must NOT commit an entry from an older term simply by counting replicas.
//! If it does, a newly elected leader with a higher term can overwrite the committed entry,
//! causing a direct linearizability / state machine safety violation.

use crucible_checkers::{CheckResult, KvOperation, OpType, SequentialRegisterChecker, LinearizabilityChecker};
use crucible_core::{NodeId, VirtualTime};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalEntry {
    pub index: u64,
    pub term: u64,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryRole {
    Follower,
    Candidate,
    Leader,
}

#[derive(Debug, Clone)]
pub struct HistoricalRaftNode {
    pub id: NodeId,
    pub current_term: u64,
    pub voted_for: Option<NodeId>,
    pub log: Vec<HistoricalEntry>,
    pub commit_index: u64,
    pub role: HistoryRole,
    pub state_machine: HashMap<String, String>,
    pub is_alive: bool,
}

impl HistoricalRaftNode {
    pub fn new(id: NodeId) -> Self {
        Self {
            id,
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            role: HistoryRole::Follower,
            state_machine: HashMap::new(),
            is_alive: true,
        }
    }

    pub fn last_log_term(&self) -> u64 {
        self.log.last().map(|e| e.term).unwrap_or(0)
    }

    pub fn last_log_index(&self) -> u64 {
        self.log.len() as u64
    }
}

/// 5-node cluster used to reproduce the historical Figure 8 consensus bug.
#[derive(Debug, Clone)]
pub struct HistoricalRaftCluster {
    pub nodes: HashMap<NodeId, HistoricalRaftNode>,
    pub current_time: VirtualTime,
    pub history: Vec<KvOperation>,
    pub isolated_nodes: Vec<NodeId>,
    pub bug_enabled: bool,
}

impl HistoricalRaftCluster {
    pub fn new(bug_enabled: bool) -> Self {
        let mut nodes = HashMap::new();
        for id in 1..=5 {
            nodes.insert(NodeId(id), HistoricalRaftNode::new(NodeId(id)));
        }
        Self {
            nodes,
            current_time: VirtualTime::ZERO,
            history: Vec::new(),
            isolated_nodes: Vec::new(),
            bug_enabled,
        }
    }

    pub fn tick_time(&mut self, nanos: u64) {
        self.current_time.advance_by(nanos);
    }

    pub fn elect_leader(&mut self, candidate_id: NodeId, term: u64, electors: &[NodeId]) -> bool {
        let candidate = match self.nodes.get_mut(&candidate_id) {
            Some(n) if n.is_alive && !self.isolated_nodes.contains(&candidate_id) => n,
            _ => return false,
        };

        let mut votes = 0;
        let cand_last_term = candidate.last_log_term();
        let cand_last_idx = candidate.last_log_index();

        for &e_id in electors {
            if let Some(elector) = self.nodes.get(&e_id) {
                if !elector.is_alive || self.isolated_nodes.contains(&e_id) {
                    continue;
                }
                // Raft §5.4.1 election restriction:
                let elector_last_term = elector.last_log_term();
                let elector_last_idx = elector.last_log_index();

                let cand_more_up_to_date = if cand_last_term != elector_last_term {
                    cand_last_term >= elector_last_term
                } else {
                    cand_last_idx >= elector_last_idx
                };

                if cand_more_up_to_date {
                    votes += 1;
                }
            }
        }

        // Needs majority of 5 (>= 3 votes)
        if votes >= 3 {
            let cand = self.nodes.get_mut(&candidate_id).unwrap();
            cand.current_term = term;
            cand.role = HistoryRole::Leader;
            cand.voted_for = Some(candidate_id);
            true
        } else {
            false
        }
    }

    /// Appends a new write to the leader's log.
    pub fn client_write(&mut self, leader_id: NodeId, key: &str, value: &str) -> bool {
        let node = match self.nodes.get_mut(&leader_id) {
            Some(n) if n.is_alive && n.role == HistoryRole::Leader && !self.isolated_nodes.contains(&leader_id) => n,
            _ => return false,
        };

        let index = node.last_log_index() + 1;
        let term = node.current_term;
        node.log.push(HistoricalEntry {
            index,
            term,
            key: key.to_string(),
            value: value.to_string(),
        });
        true
    }

    /// Replicates log from leader to target followers and attempts commit.
    pub fn replicate_to(&mut self, leader_id: NodeId, targets: &[NodeId]) {
        let (leader_log, leader_term) = {
            let leader = match self.nodes.get(&leader_id) {
                Some(n) if n.is_alive && n.role == HistoryRole::Leader => n,
                _ => return,
            };
            (leader.log.clone(), leader.current_term)
        };

        for &target_id in targets {
            if self.isolated_nodes.contains(&target_id) {
                continue;
            }
            if let Some(target) = self.nodes.get_mut(&target_id) {
                if !target.is_alive {
                    continue;
                }
                // Follower synchronizes log with leader (overwriting conflicting uncommitted entries)
                target.log = leader_log.clone();
            }
        }

        // Check replication counts and commit
        let total_nodes = self.nodes.len();
        let mut newly_committed = Vec::new();

        {
            let leader = match self.nodes.get(&leader_id) {
                Some(n) => n,
                None => return,
            };

            for entry_idx in (leader.commit_index + 1)..=leader.last_log_index() {
                let entry = &leader.log[(entry_idx - 1) as usize];
                let entry_term = entry.term;

                // Count how many alive nodes have this entry
                let mut match_count = 1; // leader has it
                for &target_id in targets {
                    if let Some(n) = self.nodes.get(&target_id) {
                        if n.is_alive && n.log.len() >= entry_idx as usize && n.log[(entry_idx - 1) as usize] == *entry {
                            match_count += 1;
                        }
                    }
                }

                let has_majority = match_count > (total_nodes / 2);

                let can_commit = if self.bug_enabled {
                    // HISTORICAL BUG: commits an older term entry by replica count alone!
                    has_majority
                } else {
                    // CORRECT RAFT §5.4.2: only commits if entry.term == current_term
                    has_majority && entry_term == leader_term
                };

                if can_commit {
                    newly_committed.push((entry_idx, entry.key.clone(), entry.value.clone()));
                }
            }
        }

        for (idx, k, v) in newly_committed {
            if let Some(leader) = self.nodes.get_mut(&leader_id) {
                leader.commit_index = idx;
                leader.state_machine.insert(k.clone(), v.clone());
            }

            // Only acknowledge client-initiated write ("x" -> "v1") as a completed client operation
            if k == "x" && v == "v1" && !self.history.iter().any(|op| op.op_type == OpType::Write && op.value.as_deref() == Some("v1")) {
                let inv = self.current_time;
                self.tick_time(10);
                let comp = self.current_time;
                self.history.push(KvOperation {
                    client_id: 1,
                    op_type: OpType::Write,
                    key: k,
                    value: Some(v),
                    invoke_time: inv,
                    complete_time: comp,
                });
            }
        }
    }

    /// Reads key from leader state machine.
    pub fn client_read(&mut self, leader_id: NodeId, key: &str) -> Option<String> {
        let node = match self.nodes.get(&leader_id) {
            Some(n) if n.is_alive && !self.isolated_nodes.contains(&leader_id) => n,
            _ => return None,
        };

        let val = node.state_machine.get(key).cloned();
        let inv = self.current_time;
        self.tick_time(10);
        let comp = self.current_time;

        self.history.push(KvOperation {
            client_id: 2,
            op_type: OpType::Read,
            key: key.to_string(),
            value: val.clone(),
            invoke_time: inv,
            complete_time: comp,
        });

        val
    }

    /// Evaluates the recorded history against the Linearizability Checker.
    pub fn verify_linearizability(&self) -> CheckResult {
        let checker = SequentialRegisterChecker;
        checker.check_history(&self.history)
    }
}

/// DSL for faults injected during the Figure 8 historical reproduction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoryFault {
    // Critical faults
    IsolateNode(NodeId),
    ReconnectNode(NodeId),
    CrashNode(NodeId),
    RecoverNode(NodeId),
    ElectLeader { candidate: NodeId, term: u64, electors: Vec<NodeId> },

    // Benign / noise faults injected during exploration
    BenignDelayPacket(NodeId, NodeId),
    BenignClockSkew(NodeId, i64),
    BenignTornWrite(NodeId, u64),
    BenignIsolateNode(NodeId),
    BenignHeal(NodeId),
}

/// Executes a fault schedule against the Figure 8 historical cluster.
/// Returns whether a linearizability violation occurred.
pub fn execute_history_schedule(faults: &[HistoryFault], bug_enabled: bool) -> (CheckResult, Vec<KvOperation>) {
    let mut cluster = HistoricalRaftCluster::new(bug_enabled);

    // Initial setup: Node 1 is leader in Term 2
    cluster.elect_leader(NodeId(1), 2, &[NodeId(1), NodeId(2), NodeId(3)]);
    cluster.client_write(NodeId(1), "x", "v1");
    // Replicate only to Node 2 (not yet majority commit)
    cluster.replicate_to(NodeId(1), &[NodeId(2)]);

    for fault in faults {
        match fault {
            HistoryFault::IsolateNode(id) => {
                if !cluster.isolated_nodes.contains(id) {
                    cluster.isolated_nodes.push(*id);
                }
            }
            HistoryFault::ReconnectNode(id) => {
                cluster.isolated_nodes.retain(|x| x != id);
            }
            HistoryFault::CrashNode(id) => {
                if let Some(n) = cluster.nodes.get_mut(id) {
                    n.is_alive = false;
                }
            }
            HistoryFault::RecoverNode(id) => {
                if let Some(n) = cluster.nodes.get_mut(id) {
                    n.is_alive = true;
                }
            }
            HistoryFault::ElectLeader { candidate, term, electors } => {
                let success = cluster.elect_leader(*candidate, *term, electors);
                if success {
                    if *candidate == NodeId(5) && *term == 3 {
                        // Leader 5 writes "x" = "v2" but doesn't replicate yet
                        cluster.client_write(NodeId(5), "x", "v2");
                    } else if *candidate == NodeId(1) && *term == 4 {
                        // Leader 1 replicates old entry (Term 2) to Node 3 -> majority {1, 2, 3}!
                        cluster.replicate_to(NodeId(1), &[NodeId(2), NodeId(3)]);
                        cluster.client_read(NodeId(1), "x");
                    } else if *candidate == NodeId(5) && *term == 5 {
                        // Leader 5 replicates its log to {3, 4, 5}, overwriting Node 3!
                        cluster.replicate_to(NodeId(5), &[NodeId(3), NodeId(4), NodeId(5)]);
                        cluster.client_read(NodeId(5), "x");
                    }
                }
            }
            HistoryFault::BenignDelayPacket(..) => {
                cluster.tick_time(50);
            }
            HistoryFault::BenignClockSkew(..) => {
                cluster.tick_time(100);
            }
            HistoryFault::BenignTornWrite(..) => {
                cluster.tick_time(10);
            }
            HistoryFault::BenignIsolateNode(id) => {
                // Affects idle node 4
                if *id == NodeId(4) && !cluster.isolated_nodes.contains(id) {
                    cluster.isolated_nodes.push(*id);
                }
            }
            HistoryFault::BenignHeal(id) => {
                cluster.isolated_nodes.retain(|x| x != id);
            }
        }
    }

    let check = cluster.verify_linearizability();
    (check, cluster.history)
}
