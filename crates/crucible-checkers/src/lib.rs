//! Crucible Checkers - Correctness property checkers (Linearizability, Serializability, Safety, Liveness).

pub mod causal;
pub use causal::*;

pub mod root_cause;
pub use root_cause::*;

pub mod elle;
pub use elle::*;

pub mod wgl;
pub use wgl::*;

use crucible_core::VirtualTime;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpType {
    Read,
    Write,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KvOperation {
    pub client_id: u32,
    pub op_type: OpType,
    pub key: String,
    pub value: Option<String>,
    pub invoke_time: VirtualTime,
    pub complete_time: VirtualTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CheckResult {
    Pass,
    Violation {
        description: String,
        minimal_history: Vec<KvOperation>,
    },
}

/// Linearizability Checker interface.
pub trait LinearizabilityChecker {
    fn check_history(&self, operations: &[KvOperation]) -> CheckResult;
}

/// Baseline Sequential Register Linearizability Checker.
pub struct SequentialRegisterChecker;

impl LinearizabilityChecker for SequentialRegisterChecker {
    fn check_history(&self, operations: &[KvOperation]) -> CheckResult {
        // Simple sanity check implementation for phase 0/1 scaffold
        let mut latest_val: Option<String> = None;
        for op in operations {
            match op.op_type {
                OpType::Write => {
                    latest_val = op.value.clone();
                }
                OpType::Read => {
                    if op.value != latest_val && latest_val.is_some() {
                        return CheckResult::Violation {
                            description: format!(
                                "Stale read detected for key {}: expected {:?}, got {:?}",
                                op.key, latest_val, op.value
                            ),
                            minimal_history: vec![op.clone()],
                        };
                    }
                }
            }
        }
        CheckResult::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linearizability_pass() {
        let checker = SequentialRegisterChecker;
        let ops = vec![
            KvOperation {
                client_id: 1,
                op_type: OpType::Write,
                key: "k1".into(),
                value: Some("v1".into()),
                invoke_time: VirtualTime(10),
                complete_time: VirtualTime(20),
            },
            KvOperation {
                client_id: 2,
                op_type: OpType::Read,
                key: "k1".into(),
                value: Some("v1".into()),
                invoke_time: VirtualTime(25),
                complete_time: VirtualTime(30),
            },
        ];
        assert_eq!(checker.check_history(&ops), CheckResult::Pass);
    }

    #[test]
    fn test_linearizability_stale_read() {
        let checker = SequentialRegisterChecker;
        let ops = vec![
            KvOperation {
                client_id: 1,
                op_type: OpType::Write,
                key: "k1".into(),
                value: Some("v2".into()),
                invoke_time: VirtualTime(10),
                complete_time: VirtualTime(20),
            },
            KvOperation {
                client_id: 2,
                op_type: OpType::Read,
                key: "k1".into(),
                value: Some("v1".into()),
                invoke_time: VirtualTime(25),
                complete_time: VirtualTime(30),
            },
        ];
        match checker.check_history(&ops) {
            CheckResult::Violation { description, .. } => {
                assert!(description.contains("Stale read detected"));
            }
            CheckResult::Pass => panic!("Expected violation"),
        }
    }
}
