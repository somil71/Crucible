//! WGL (Wing & Gong) Concurrent Register Linearizability Checker.
//!
//! Checks whether a concurrent execution trace of Read/Write operations on registers
//! can be linearized according to a sequential specification while respecting
//! the real-time partial order: (complete_a < invoke_b => a must precede b).

use crate::{CheckResult, KvOperation, LinearizabilityChecker, OpType};
use std::collections::{HashMap, HashSet};

pub struct WglLinearizabilityChecker;

impl LinearizabilityChecker for WglLinearizabilityChecker {
    fn check_history(&self, operations: &[KvOperation]) -> CheckResult {
        if operations.is_empty() {
            return CheckResult::Pass;
        }

        // 1. Partition operations by key
        let mut by_key: HashMap<String, Vec<KvOperation>> = HashMap::new();
        for op in operations {
            by_key.entry(op.key.clone()).or_default().push(op.clone());
        }

        // 2. Check each key independently
        for (key, key_ops) in by_key {
            if let Err(violation) = check_single_key(&key, &key_ops) {
                return violation;
            }
        }

        CheckResult::Pass
    }
}

fn check_single_key(key: &str, ops: &[KvOperation]) -> Result<(), CheckResult> {
    let n = ops.len();
    if n == 0 {
        return Ok(());
    }

    // Sort operations primarily by invocation time for search stability
    let mut sorted_ops = ops.to_vec();
    sorted_ops.sort_by_key(|op| (op.invoke_time, op.complete_time));

    // Precompute happens-before matrix: hb[i][j] is true if ops[i] strictly precedes ops[j]
    // i.e., complete_i < invoke_j
    let mut hb = vec![vec![false; n]; n];
    for i in 0..n {
        for j in 0..n {
            if i != j && sorted_ops[i].complete_time < sorted_ops[j].invoke_time {
                hb[i][j] = true;
            }
        }
    }

    // Memoization set of visited (unlinearized_bitmask, current_value) that failed
    let mut visited_failures: HashSet<(u64, Option<String>)> = HashSet::new();

    let initial_mask = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
    let initial_val: Option<String> = None;

    let success = if n <= 64 {
        search_wgl(
            initial_mask,
            initial_val,
            &sorted_ops,
            &hb,
            &mut visited_failures,
        )
    } else {
        let mut visited_dyn = HashSet::new();
        let initial_dyn = vec![true; n];
        search_wgl_dynamic(
            &initial_dyn,
            initial_val,
            &sorted_ops,
            &hb,
            &mut visited_dyn,
        )
    };

    if success {
        Ok(())
    } else {
        Err(CheckResult::Violation {
            description: format!(
                "Non-linearizable execution detected for register key '{}': no valid sequential order satisfies real-time constraints",
                key
            ),
            minimal_history: sorted_ops,
        })
    }
}

fn search_wgl(
    unlinearized_mask: u64,
    current_val: Option<String>,
    ops: &[KvOperation],
    hb: &[Vec<bool>],
    visited_failures: &mut HashSet<(u64, Option<String>)>,
) -> bool {
    if unlinearized_mask == 0 {
        // All operations successfully linearized!
        return true;
    }

    let state_key = (unlinearized_mask, current_val.clone());
    if visited_failures.contains(&state_key) {
        return false;
    }

    let n = ops.len();

    // Find candidate operations that can be linearized next:
    // An operation i is a candidate if:
    // 1. It is unlinearized (bit i is 1)
    // 2. No other unlinearized operation j must precede i (i.e. hb[j][i] is false for all unlinearized j)
    for i in 0..n {
        if (unlinearized_mask & (1u64 << i)) == 0 {
            continue; // already linearized
        }

        // Check if any remaining unlinearized op must strictly precede op i
        let mut blocked = false;
        for j in 0..n {
            if i != j && (unlinearized_mask & (1u64 << j)) != 0 && hb[j][i] {
                blocked = true;
                break;
            }
        }

        if blocked {
            continue;
        }

        // Check if op i is legally valid in the current register state
        let op = &ops[i];
        let (valid, next_val) = match op.op_type {
            OpType::Write => (true, op.value.clone()),
            OpType::Read => {
                // Sequential register specification: Read must return current value
                let matches = op.value == current_val;
                (matches, current_val.clone())
            }
        };

        if valid {
            let next_mask = unlinearized_mask & !(1u64 << i);
            if search_wgl(next_mask, next_val, ops, hb, visited_failures) {
                return true;
            }
        }
    }

    visited_failures.insert(state_key);
    false
}

fn search_wgl_dynamic(
    unlinearized: &[bool],
    current_val: Option<String>,
    ops: &[KvOperation],
    hb: &[Vec<bool>],
    visited_failures: &mut HashSet<(Vec<bool>, Option<String>)>,
) -> bool {
    if !unlinearized.iter().any(|&b| b) {
        return true;
    }

    let state_key = (unlinearized.to_vec(), current_val.clone());
    if visited_failures.contains(&state_key) {
        return false;
    }

    let n = ops.len();

    for i in 0..n {
        if !unlinearized[i] {
            continue;
        }

        let mut blocked = false;
        for j in 0..n {
            if i != j && unlinearized[j] && hb[j][i] {
                blocked = true;
                break;
            }
        }

        if blocked {
            continue;
        }

        let op = &ops[i];
        let (valid, next_val) = match op.op_type {
            OpType::Write => (true, op.value.clone()),
            OpType::Read => {
                let matches = op.value == current_val;
                (matches, current_val.clone())
            }
        };

        if valid {
            let mut next_unlin = unlinearized.to_vec();
            next_unlin[i] = false;
            if search_wgl_dynamic(&next_unlin, next_val, ops, hb, visited_failures) {
                return true;
            }
        }
    }

    visited_failures.insert(state_key);
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_core::VirtualTime;

    #[test]
    fn test_wgl_sequential_pass() {
        let checker = WglLinearizabilityChecker;
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
                invoke_time: VirtualTime(30),
                complete_time: VirtualTime(40),
            },
        ];

        assert_eq!(checker.check_history(&ops), CheckResult::Pass);
    }

    #[test]
    fn test_wgl_concurrent_overlapping_read_write_pass() {
        // Write v1 [10..50]
        // Read v1  [20..30] -> concurrent with Write! Can be linearized after Write.
        let checker = WglLinearizabilityChecker;
        let ops = vec![
            KvOperation {
                client_id: 1,
                op_type: OpType::Write,
                key: "x".into(),
                value: Some("v1".into()),
                invoke_time: VirtualTime(10),
                complete_time: VirtualTime(50),
            },
            KvOperation {
                client_id: 2,
                op_type: OpType::Read,
                key: "x".into(),
                value: Some("v1".into()),
                invoke_time: VirtualTime(20),
                complete_time: VirtualTime(30),
            },
        ];

        assert_eq!(checker.check_history(&ops), CheckResult::Pass);
    }

    #[test]
    fn test_wgl_stale_read_violation() {
        // Write v1 [10..20] completes strictly before Read None [30..40] is invoked.
        // Read returning None violates real-time order!
        let checker = WglLinearizabilityChecker;
        let ops = vec![
            KvOperation {
                client_id: 1,
                op_type: OpType::Write,
                key: "x".into(),
                value: Some("v1".into()),
                invoke_time: VirtualTime(10),
                complete_time: VirtualTime(20),
            },
            KvOperation {
                client_id: 2,
                op_type: OpType::Read,
                key: "x".into(),
                value: None,
                invoke_time: VirtualTime(30),
                complete_time: VirtualTime(40),
            },
        ];

        assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
    }

    #[test]
    fn test_wgl_concurrent_writes_valid() {
        // Two concurrent writes: Write("A") [10..50], Write("B") [10..50]
        // Read("B") [60..70]
        // Can be linearized as Write("A"), Write("B"), Read("B").
        let checker = WglLinearizabilityChecker;
        let ops = vec![
            KvOperation {
                client_id: 1,
                op_type: OpType::Write,
                key: "reg".into(),
                value: Some("A".into()),
                invoke_time: VirtualTime(10),
                complete_time: VirtualTime(50),
            },
            KvOperation {
                client_id: 2,
                op_type: OpType::Write,
                key: "reg".into(),
                value: Some("B".into()),
                invoke_time: VirtualTime(10),
                complete_time: VirtualTime(50),
            },
            KvOperation {
                client_id: 3,
                op_type: OpType::Read,
                key: "reg".into(),
                value: Some("B".into()),
                invoke_time: VirtualTime(60),
                complete_time: VirtualTime(70),
            },
        ];

        assert_eq!(checker.check_history(&ops), CheckResult::Pass);
    }
}
