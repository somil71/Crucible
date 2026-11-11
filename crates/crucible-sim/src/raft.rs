//! Toy Raft Consensus Engine with Seeded Split-Brain Joint Consensus Bug.

use crucible_core::{NodeId, VirtualTime};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub index: usize,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterConfig {
    Single(Vec<NodeId>),
    Joint {
        old_config: Vec<NodeId>,
        new_config: Vec<NodeId>,
    },
}

impl ClusterConfig {
    pub fn contains(&self, id: NodeId) -> bool {
        match self {
            Self::Single(nodes) => nodes.contains(&id),
            Self::Joint { old_config, new_config } => {
                old_config.contains(&id) || new_config.contains(&id)
            }
        }
    }

    pub fn all_nodes(&self) -> Vec<NodeId> {
        match self {
            Self::Single(nodes) => nodes.clone(),
            Self::Joint { old_config, new_config } => {
                let mut all = old_config.clone();
                for &n in new_config {
                    if !all.contains(&n) {
                        all.push(n);
                    }
                }
                all
            }
        }
    }

    /// Evaluates whether a set of votes constitutes a majority.
    /// In strict joint consensus, majorities from BOTH old and new configs are required.
    /// If `seeded_bug` is true, a candidate only checks the majority of its own sub-configuration.
    pub fn is_majority(&self, candidate_id: NodeId, votes: &HashSet<NodeId>, seeded_bug: bool) -> bool {
        match self {
            Self::Single(nodes) => {
                let count = nodes.iter().filter(|n| votes.contains(n)).count();
                count > nodes.len() / 2
            }
            Self::Joint { old_config, new_config } => {
                let old_count = old_config.iter().filter(|n| votes.contains(n)).count();
                let old_majority = old_count > old_config.len() / 2;

                let new_count = new_config.iter().filter(|n| votes.contains(n)).count();
                let new_majority = new_count > new_config.len() / 2;

                if seeded_bug {
                    // BUG: Candidate only requires a majority in its own sub-configuration
                    if old_config.contains(&candidate_id) && !new_config.contains(&candidate_id) {
                        old_majority
                    } else if new_config.contains(&candidate_id) && !old_config.contains(&candidate_id) {
                        new_majority
                    } else {
                        old_majority || new_majority
                    }
                } else {
                    // Correct Raft: must win majorities in BOTH configs independently
                    old_majority && new_majority
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftMessage {
    RequestVote {
        term: u64,
        candidate_id: NodeId,
        last_log_index: usize,
        last_log_term: u64,
    },
    RequestVoteReply {
        term: u64,
        vote_granted: bool,
    },
    AppendEntries {
        term: u64,
        leader_id: NodeId,
        prev_log_index: usize,
        prev_log_term: u64,
        entries: Vec<LogEntry>,
        leader_commit: usize,
    },
    AppendEntriesReply {
        term: u64,
        success: bool,
        match_index: usize,
    },
    ProposeCommand(String),
}

pub struct RaftNode {
    pub id: NodeId,
    pub current_term: u64,
    pub voted_for: Option<NodeId>,
    pub role: Role,
    pub log: Vec<LogEntry>,
    pub commit_index: usize,
    pub last_applied: usize,
    pub config: ClusterConfig,
    pub votes_received: HashSet<NodeId>,
    pub seeded_bug: bool,
    pub next_election_timeout: VirtualTime,
}

impl RaftNode {
    pub fn new(id: NodeId, config: ClusterConfig, seeded_bug: bool) -> Self {
        Self {
            id,
            current_term: 0,
            voted_for: None,
            role: Role::Follower,
            log: Vec::new(),
            commit_index: 0,
            last_applied: 0,
            config,
            votes_received: HashSet::new(),
            seeded_bug,
            next_election_timeout: VirtualTime(150_000_000), // 150ms
        }
    }

    /// Handles an incoming Raft message and returns any outgoing responses.
    pub fn handle_message(
        &mut self,
        from: NodeId,
        msg: RaftMessage,
        now: VirtualTime,
    ) -> Vec<(NodeId, RaftMessage)> {
        let mut outgoing = Vec::new();

        match msg {
            RaftMessage::RequestVote {
                term,
                candidate_id,
                last_log_index,
                last_log_term,
            } => {
                if term > self.current_term {
                    self.current_term = term;
                    self.role = Role::Follower;
                    self.voted_for = None;
                }

                let can_vote = (self.voted_for.is_none() || self.voted_for == Some(candidate_id))
                    && term == self.current_term;

                let my_last_log_term = self.log.last().map(|e| e.term).unwrap_or(0);
                let my_last_log_index = self.log.len();

                let up_to_date = last_log_term > my_last_log_term
                    || (last_log_term == my_last_log_term && last_log_index >= my_last_log_index);

                let grant = can_vote && up_to_date;
                if grant {
                    self.voted_for = Some(candidate_id);
                    self.next_election_timeout = VirtualTime(now.0 + 150_000_000);
                }

                outgoing.push((
                    from,
                    RaftMessage::RequestVoteReply {
                        term: self.current_term,
                        vote_granted: grant,
                    },
                ));
            }
            RaftMessage::RequestVoteReply { term, vote_granted } => {
                if term > self.current_term {
                    self.current_term = term;
                    self.role = Role::Follower;
                    self.voted_for = None;
                    return outgoing;
                }

                if self.role == Role::Candidate && term == self.current_term && vote_granted {
                    self.votes_received.insert(from);
                    if self.config.is_majority(self.id, &self.votes_received, self.seeded_bug) {
                        self.role = Role::Leader;
                    }
                }
            }
            RaftMessage::AppendEntries {
                term,
                leader_id: _,
                prev_log_index,
                prev_log_term,
                entries,
                leader_commit,
            } => {
                if term >= self.current_term {
                    if term > self.current_term || self.role == Role::Candidate {
                        self.role = Role::Follower;
                    }
                    self.current_term = term;
                    self.next_election_timeout = VirtualTime(now.0 + 150_000_000);
                } else {
                    outgoing.push((
                        from,
                        RaftMessage::AppendEntriesReply {
                            term: self.current_term,
                            success: false,
                            match_index: self.log.len(),
                        },
                    ));
                    return outgoing;
                }

                // Check prev log term
                if prev_log_index > 0 {
                    if self.log.len() < prev_log_index {
                        outgoing.push((
                            from,
                            RaftMessage::AppendEntriesReply {
                                term: self.current_term,
                                success: false,
                                match_index: self.log.len(),
                            },
                        ));
                        return outgoing;
                    }
                    if self.log[prev_log_index - 1].term != prev_log_term {
                        self.log.truncate(prev_log_index - 1);
                        outgoing.push((
                            from,
                            RaftMessage::AppendEntriesReply {
                                term: self.current_term,
                                success: false,
                                match_index: self.log.len(),
                            },
                        ));
                        return outgoing;
                    }
                }

                for entry in entries {
                    let idx = entry.index;
                    if idx <= self.log.len() {
                        self.log[idx - 1] = entry;
                    } else {
                        self.log.push(entry);
                    }
                }

                if leader_commit > self.commit_index {
                    self.commit_index = leader_commit.min(self.log.len());
                }

                outgoing.push((
                    from,
                    RaftMessage::AppendEntriesReply {
                        term: self.current_term,
                        success: true,
                        match_index: self.log.len(),
                    },
                ));
            }
            RaftMessage::AppendEntriesReply { term, success, match_index } => {
                if term > self.current_term {
                    self.current_term = term;
                    self.role = Role::Follower;
                    self.voted_for = None;
                    return outgoing;
                }

                if self.role == Role::Leader && success && match_index > self.commit_index {
                    // Update commit index on majority match
                    self.commit_index = match_index;
                }
            }
            RaftMessage::ProposeCommand(cmd) => {
                if self.role == Role::Leader {
                    let index = self.log.len() + 1;
                    let prev_log_term = if index > 1 { self.log[index - 2].term } else { 0 };
                    let entry = LogEntry {
                        term: self.current_term,
                        index,
                        command: cmd,
                    };
                    self.log.push(entry.clone());

                    for peer in self.config.all_nodes() {
                        if peer != self.id {
                            outgoing.push((
                                peer,
                                RaftMessage::AppendEntries {
                                    term: self.current_term,
                                    leader_id: self.id,
                                    prev_log_index: index - 1,
                                    prev_log_term,
                                    entries: vec![entry.clone()],
                                    leader_commit: self.commit_index,
                                },
                            ));
                        }
                    }
                }
            }
        }

        outgoing
    }

    /// Triggers an election when the election timer expires.
    pub fn trigger_election(&mut self, now: VirtualTime) -> Vec<(NodeId, RaftMessage)> {
        self.role = Role::Candidate;
        self.current_term += 1;
        self.voted_for = Some(self.id);
        self.votes_received.clear();
        self.votes_received.insert(self.id);
        self.next_election_timeout = VirtualTime(now.0 + 150_000_000);

        let last_log_term = self.log.last().map(|e| e.term).unwrap_or(0);
        let last_log_index = self.log.len();

        let mut broadcasts = Vec::new();
        let peers = match &self.config {
            ClusterConfig::Single(nodes) => nodes.clone(),
            ClusterConfig::Joint { old_config, new_config } => {
                let mut set: HashSet<NodeId> = old_config.iter().copied().collect();
                set.extend(new_config.iter().copied());
                set.into_iter().collect()
            }
        };

        for peer in peers {
            if peer != self.id {
                broadcasts.push((
                    peer,
                    RaftMessage::RequestVote {
                        term: self.current_term,
                        candidate_id: self.id,
                        last_log_index,
                        last_log_term,
                    },
                ));
            }
        }

        // If single-node cluster, immediately become leader
        if self.config.is_majority(self.id, &self.votes_received, self.seeded_bug) {
            self.role = Role::Leader;
        }

        broadcasts
    }
}
