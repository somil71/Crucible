//! Elle-Style Transaction Isolation & Serialization Graph Cycle Detector.
//!
//! Based on Kingsbury & Alvaro (VLDB 2020), Elle infers direct dependencies
//! between transactions (wr, ww, rw) and searches for directed cycles
//! to detect isolation anomalies:
//! - G0 (Dirty Write): cycles of write-write (ww) dependencies.
//! - G1c (Circular Information Flow): cycles of wr and ww dependencies.
//! - G2 (Write Skew / Anti-dependency): cycles containing at least one rw anti-dependency.

use crucible_core::VirtualTime;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxOp {
    Read { key: String, value: Option<String> },
    Write { key: String, value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub id: TxId,
    pub ops: Vec<TxOp>,
    pub start_time: VirtualTime,
    pub commit_time: VirtualTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeType {
    /// Write-Read: T1 writes x, T2 reads x
    Wr,
    /// Write-Write: T1 writes x, T2 subsequently overwrites x
    Ww,
    /// Read-Write (Anti-dependency): T1 reads x, T2 subsequently overwrites x with newer version
    Rw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DependencyEdge {
    pub from: TxId,
    pub to: TxId,
    pub edge_type: EdgeType,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElleAnomaly {
    /// G0: Dirty write cycle (ww edges only)
    G0DirtyWrite { cycle: Vec<TxId> },
    /// G1c: Circular information flow (wr and ww edges)
    G1cCircularInfoFlow { cycle: Vec<TxId> },
    /// G2: Anti-dependency cycle (contains rw edges, e.g. Write Skew under Snapshot Isolation)
    G2AntiDependency { cycle: Vec<TxId> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElleCheckResult {
    Serializable,
    AnomalyDetected(ElleAnomaly),
}

pub struct ElleCycleDetector;

impl ElleCycleDetector {
    /// Constructs the Direct Serialization Graph (DSG) and checks for isolation anomalies.
    pub fn check_transactions(txs: &[Transaction]) -> ElleCheckResult {
        if txs.len() <= 1 {
            return ElleCheckResult::Serializable;
        }

        let dsg_edges = Self::build_dsg(txs);
        Self::detect_anomalies(txs, &dsg_edges)
    }

    /// Infers wr, ww, and rw dependencies across transactions.
    pub fn build_dsg(txs: &[Transaction]) -> Vec<DependencyEdge> {
        let mut edges = Vec::new();

        // Map key -> chronological list of (TxId, written_value, write_time)
        let mut key_writes: HashMap<String, Vec<(TxId, String, VirtualTime)>> = HashMap::new();
        // Map key -> list of (TxId, read_value, read_time)
        let mut key_reads: HashMap<String, Vec<(TxId, Option<String>, VirtualTime)>> = HashMap::new();

        for tx in txs {
            let mut tx_final_writes: HashMap<String, String> = HashMap::new();
            for op in &tx.ops {
                match op {
                    TxOp::Write { key, value } => {
                        tx_final_writes.insert(key.clone(), value.clone());
                    }
                    TxOp::Read { key, value } => {
                        key_reads
                            .entry(key.clone())
                            .or_default()
                            .push((tx.id, value.clone(), tx.start_time));
                    }
                }
            }

            for (key, value) in tx_final_writes {
                key_writes
                    .entry(key)
                    .or_default()
                    .push((tx.id, value, tx.commit_time));
            }
        }

        // Sort writes per key by commit time to establish version order
        for (key, writes) in &mut key_writes {
            writes.sort_by_key(|w| w.2);

            // 1. Write-Write (ww) edges: T_i -> T_{i+1}
            for i in 0..writes.len() {
                for j in (i + 1)..writes.len() {
                    let (tx1, _, _) = writes[i];
                    let (tx2, _, _) = writes[j];
                    if tx1 != tx2 {
                        edges.push(DependencyEdge {
                            from: tx1,
                            to: tx2,
                            edge_type: EdgeType::Ww,
                            key: key.clone(),
                        });
                    }
                }
            }
        }

        // 2. Write-Read (wr) edges: T_w writes v, T_r reads v
        for (key, reads) in &key_reads {
            if let Some(writes) = key_writes.get(key) {
                for (r_tx, r_val, _) in reads {
                    if let Some(val) = r_val {
                        for (w_tx, w_val, _) in writes {
                            if w_tx != r_tx && w_val == val {
                                edges.push(DependencyEdge {
                                    from: *w_tx,
                                    to: *r_tx,
                                    edge_type: EdgeType::Wr,
                                    key: key.clone(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // 3. Read-Write (rw) anti-dependencies: T_r reads version v, T_w overwrites v with newer version
        for (key, reads) in &key_reads {
            if let Some(writes) = key_writes.get(key) {
                for (r_tx, r_val, _) in reads {
                    let start_w = if let Some(val) = r_val {
                        let mut found_idx = None;
                        for (idx, (_, w_val, _)) in writes.iter().enumerate() {
                            if w_val == val {
                                found_idx = Some(idx);
                                break;
                            }
                        }
                        if let Some(idx) = found_idx {
                            idx + 1
                        } else {
                            // Read an initial value (before any transaction in trace wrote)
                            0
                        }
                    } else {
                        // Read None (initial empty state)
                        0
                    };

                    for (w_tx, _, _) in &writes[start_w..] {
                        if r_tx != w_tx {
                            edges.push(DependencyEdge {
                                from: *r_tx,
                                to: *w_tx,
                                edge_type: EdgeType::Rw,
                                key: key.clone(),
                            });
                        }
                    }
                }
            }
        }

        // Deduplicate edges
        let mut unique_edges = Vec::new();
        let mut seen = HashSet::new();
        for edge in edges {
            let key = (edge.from, edge.to, edge.edge_type, edge.key.clone());
            if seen.insert(key) {
                unique_edges.push(edge);
            }
        }

        unique_edges
    }

    /// Detects directed cycles in the DSG and classifies the isolation anomaly.
    fn detect_anomalies(txs: &[Transaction], edges: &[DependencyEdge]) -> ElleCheckResult {
        let mut adj: BTreeMap<TxId, Vec<(TxId, EdgeType)>> = BTreeMap::new();
        for tx in txs {
            adj.entry(tx.id).or_default();
        }
        for edge in edges {
            adj.entry(edge.from).or_default().push((edge.to, edge.edge_type));
        }

        // Tarjan's / DFS cycle detection
        let mut visited: HashMap<TxId, usize> = HashMap::new(); // 0 = unvisited, 1 = visiting, 2 = visited
        let mut path: Vec<(TxId, EdgeType)> = Vec::new();

        for tx in txs {
            if visited.get(&tx.id).copied().unwrap_or(0) == 0 {
                if let Some(cycle_edges) = Self::find_cycle(tx.id, &adj, &mut visited, &mut path) {
                    let has_rw = cycle_edges.iter().any(|(_, t)| *t == EdgeType::Rw);
                    let has_wr = cycle_edges.iter().any(|(_, t)| *t == EdgeType::Wr);
                    let all_ww = cycle_edges.iter().all(|(_, t)| *t == EdgeType::Ww);

                    let cycle_nodes: Vec<TxId> = cycle_edges.iter().map(|(id, _)| *id).collect();

                    if all_ww {
                        return ElleCheckResult::AnomalyDetected(ElleAnomaly::G0DirtyWrite {
                            cycle: cycle_nodes,
                        });
                    } else if has_rw {
                        return ElleCheckResult::AnomalyDetected(ElleAnomaly::G2AntiDependency {
                            cycle: cycle_nodes,
                        });
                    } else if has_wr {
                        return ElleCheckResult::AnomalyDetected(ElleAnomaly::G1cCircularInfoFlow {
                            cycle: cycle_nodes,
                        });
                    }
                }
            }
        }

        ElleCheckResult::Serializable
    }

    fn find_cycle(
        curr: TxId,
        adj: &BTreeMap<TxId, Vec<(TxId, EdgeType)>>,
        visited: &mut HashMap<TxId, usize>,
        path: &mut Vec<(TxId, EdgeType)>,
    ) -> Option<Vec<(TxId, EdgeType)>> {
        visited.insert(curr, 1); // mark in-progress (visiting)

        if let Some(neighbors) = adj.get(&curr) {
            for &(next, edge_type) in neighbors {
                let status = visited.get(&next).copied().unwrap_or(0);
                if status == 1 {
                    // Cycle detected! Extract path from next to curr
                    let mut cycle = Vec::new();
                    let start_idx = path.iter().position(|(id, _)| *id == next).unwrap_or(0);
                    for item in &path[start_idx..] {
                        cycle.push(*item);
                    }
                    cycle.push((curr, edge_type));
                    return Some(cycle);
                } else if status == 0 {
                    path.push((curr, edge_type));
                    if let Some(cycle) = Self::find_cycle(next, adj, visited, path) {
                        return Some(cycle);
                    }
                    path.pop();
                }
            }
        }

        visited.insert(curr, 2); // mark finished
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elle_serializable_txs_pass() {
        // T1 writes x=1
        // T2 reads x=1, writes y=2
        // T3 reads y=2
        // Strict linear sequence, no cycles.
        let txs = vec![
            Transaction {
                id: TxId(1),
                ops: vec![TxOp::Write { key: "x".into(), value: "1".into() }],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(20),
            },
            Transaction {
                id: TxId(2),
                ops: vec![
                    TxOp::Read { key: "x".into(), value: Some("1".into()) },
                    TxOp::Write { key: "y".into(), value: "2".into() },
                ],
                start_time: VirtualTime(30),
                commit_time: VirtualTime(40),
            },
            Transaction {
                id: TxId(3),
                ops: vec![TxOp::Read { key: "y".into(), value: Some("2".into()) }],
                start_time: VirtualTime(50),
                commit_time: VirtualTime(60),
            },
        ];

        let result = ElleCycleDetector::check_transactions(&txs);
        assert_eq!(result, ElleCheckResult::Serializable);
    }

    #[test]
    fn test_elle_g2_write_skew_anomaly() {
        // Classic Write Skew (Snapshot Isolation anomaly):
        // Initial: x=0, y=0.
        // T1 reads y=0, writes x=1
        // T2 reads x=0, writes y=1
        // T1 -rw-> T2 (T1 read y=0, T2 overwrote y with 1)
        // T2 -rw-> T1 (T2 read x=0, T1 overwrote x with 1)
        // Cycle: T1 -rw-> T2 -rw-> T1 -> G2 Anti-Dependency cycle!
        let txs = vec![
            Transaction {
                id: TxId(1),
                ops: vec![
                    TxOp::Read { key: "y".into(), value: Some("0".into()) },
                    TxOp::Write { key: "x".into(), value: "1".into() },
                ],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(30),
            },
            Transaction {
                id: TxId(2),
                ops: vec![
                    TxOp::Read { key: "x".into(), value: Some("0".into()) },
                    TxOp::Write { key: "y".into(), value: "1".into() },
                ],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(30),
            },
        ];

        let result = ElleCycleDetector::check_transactions(&txs);
        match result {
            ElleCheckResult::AnomalyDetected(ElleAnomaly::G2AntiDependency { cycle }) => {
                assert!(cycle.contains(&TxId(1)));
                assert!(cycle.contains(&TxId(2)));
            }
            other => panic!("Expected G2 Anti-Dependency cycle, got {:?}", other),
        }
    }

    #[test]
    fn test_elle_g1c_circular_information_flow() {
        // T1 writes x=1, reads y=2
        // T2 writes y=2, reads x=1
        // T1 -wr-> T2 (T2 read x=1 from T1)
        // T2 -wr-> T1 (T1 read y=2 from T2)
        // Cycle: T1 -> T2 -> T1 (wr edges) -> G1c!
        let txs = vec![
            Transaction {
                id: TxId(1),
                ops: vec![
                    TxOp::Write { key: "x".into(), value: "1".into() },
                    TxOp::Read { key: "y".into(), value: Some("2".into()) },
                ],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(30),
            },
            Transaction {
                id: TxId(2),
                ops: vec![
                    TxOp::Write { key: "y".into(), value: "2".into() },
                    TxOp::Read { key: "x".into(), value: Some("1".into()) },
                ],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(30),
            },
        ];

        let result = ElleCycleDetector::check_transactions(&txs);
        match result {
            ElleCheckResult::AnomalyDetected(ElleAnomaly::G1cCircularInfoFlow { cycle }) => {
                assert!(cycle.contains(&TxId(1)));
                assert!(cycle.contains(&TxId(2)));
            }
            other => panic!("Expected G1c cycle, got {:?}", other),
        }
    }

    #[test]
    fn test_elle_g0_dirty_write_cycle() {
        let edges = vec![
            DependencyEdge {
                from: TxId(1),
                to: TxId(2),
                edge_type: EdgeType::Ww,
                key: "x".into(),
            },
            DependencyEdge {
                from: TxId(2),
                to: TxId(1),
                edge_type: EdgeType::Ww,
                key: "y".into(),
            },
        ];
        let txs = vec![
            Transaction {
                id: TxId(1),
                ops: vec![],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(20),
            },
            Transaction {
                id: TxId(2),
                ops: vec![],
                start_time: VirtualTime(10),
                commit_time: VirtualTime(20),
            },
        ];
        let result = ElleCycleDetector::detect_anomalies(&txs, &edges);
        match result {
            ElleCheckResult::AnomalyDetected(ElleAnomaly::G0DirtyWrite { cycle }) => {
                assert!(cycle.contains(&TxId(1)));
                assert!(cycle.contains(&TxId(2)));
            }
            other => panic!("Expected G0 Dirty Write cycle, got {:?}", other),
        }
    }
}
