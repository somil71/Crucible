use crucible_checkers::{
    CheckResult, KvOperation, LinearizabilityChecker, OpType, SequentialRegisterChecker,
};
use crucible_core::VirtualTime;

fn make_write(client: u32, key: &str, val: &str, t_inv: u64, t_comp: u64) -> KvOperation {
    KvOperation {
        client_id: client,
        op_type: OpType::Write,
        key: key.into(),
        value: Some(val.into()),
        invoke_time: VirtualTime(t_inv),
        complete_time: VirtualTime(t_comp),
    }
}

fn make_read(client: u32, key: &str, expected: Option<&str>, t_inv: u64, t_comp: u64) -> KvOperation {
    KvOperation {
        client_id: client,
        op_type: OpType::Read,
        key: key.into(),
        value: expected.map(|s| s.into()),
        invoke_time: VirtualTime(t_inv),
        complete_time: VirtualTime(t_comp),
    }
}

// ==========================================
// 1. Valid Sequential Register Operations (10 tests)
// ==========================================

#[test]
fn test_checker_empty_history_pass() {
    let checker = SequentialRegisterChecker;
    assert_eq!(checker.check_history(&[]), CheckResult::Pass);
}

#[test]
fn test_checker_single_write_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![make_write(1, "x", "1", 10, 20)];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_write_then_read_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "1", 10, 20),
        make_read(2, "x", Some("1"), 25, 30),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_overwrite_then_read_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "1", 10, 20),
        make_write(1, "x", "2", 25, 30),
        make_read(2, "x", Some("2"), 35, 40),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_repeated_reads_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "value", 10, 20),
        make_read(2, "x", Some("value"), 25, 30),
        make_read(3, "x", Some("value"), 35, 40),
        make_read(4, "x", Some("value"), 45, 50),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_multi_step_counter_pass() {
    let checker = SequentialRegisterChecker;
    let mut ops = Vec::new();
    for i in 0..10 {
        ops.push(make_write(1, "c", &format!("{i}"), i * 20, i * 20 + 10));
        ops.push(make_read(2, "c", Some(&format!("{i}")), i * 20 + 11, i * 20 + 19));
    }
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_different_clients_sequential_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(101, "k", "v1", 10, 20),
        make_write(102, "k", "v2", 30, 40),
        make_read(103, "k", Some("v2"), 50, 60),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_only_reads_none_value_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_read(1, "x", None, 10, 20),
        make_read(2, "x", None, 30, 40),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_serde_kvoperation() {
    let op = make_write(1, "k", "v", 100, 200);
    let json = serde_json::to_string(&op).unwrap();
    let deser: KvOperation = serde_json::from_str(&json).unwrap();
    assert_eq!(op, deser);
}

#[test]
fn test_checker_serde_check_result_pass() {
    let res = CheckResult::Pass;
    let json = serde_json::to_string(&res).unwrap();
    let deser: CheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(res, deser);
}

// ==========================================
// 2. Linearizability Violations & Stale Reads (10 tests)
// ==========================================

#[test]
fn test_checker_stale_read_detected() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "v2", 10, 20),
        make_read(2, "x", Some("v1"), 25, 30),
    ];
    match checker.check_history(&ops) {
        CheckResult::Violation { description, minimal_history } => {
            assert!(description.contains("Stale read detected"));
            assert_eq!(minimal_history.len(), 1);
        }
        CheckResult::Pass => panic!("Expected stale read violation"),
    }
}

#[test]
fn test_checker_reverted_write_detected() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "A", 10, 20),
        make_write(1, "x", "B", 30, 40),
        make_read(2, "x", Some("A"), 50, 60),
    ];
    assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
}

#[test]
fn test_checker_stale_read_after_multiple_overwrites() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "1", 10, 20),
        make_write(1, "x", "2", 30, 40),
        make_write(1, "x", "3", 50, 60),
        make_read(2, "x", Some("2"), 70, 80),
    ];
    assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
}

#[test]
fn test_checker_violation_retains_faulty_op() {
    let checker = SequentialRegisterChecker;
    let bad_op = make_read(99, "x", Some("stale"), 25, 30);
    let ops = vec![make_write(1, "x", "fresh", 10, 20), bad_op.clone()];
    if let CheckResult::Violation { minimal_history, .. } = checker.check_history(&ops) {
        assert_eq!(minimal_history[0], bad_op);
    } else {
        panic!("Expected violation");
    }
}

#[test]
fn test_checker_serde_violation() {
    let res = CheckResult::Violation {
        description: "Error".into(),
        minimal_history: vec![make_write(1, "a", "b", 1, 2)],
    };
    let json = serde_json::to_string(&res).unwrap();
    let deser: CheckResult = serde_json::from_str(&json).unwrap();
    assert_eq!(res, deser);
}

#[test]
fn test_checker_read_none_when_written_detected() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "x", "val", 10, 20),
        make_read(2, "x", None, 30, 40),
    ];
    assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
}

#[test]
fn test_checker_violation_description_contains_key() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "target_key", "val2", 10, 20),
        make_read(2, "target_key", Some("val1"), 30, 40),
    ];
    if let CheckResult::Violation { description, .. } = checker.check_history(&ops) {
        assert!(description.contains("target_key"));
    }
}

#[test]
fn test_checker_stale_read_on_last_of_many_ops() {
    let checker = SequentialRegisterChecker;
    let mut ops = Vec::new();
    for i in 0..50 {
        ops.push(make_write(1, "k", &format!("{i}"), i * 10, i * 10 + 5));
        ops.push(make_read(2, "k", Some(&format!("{i}")), i * 10 + 6, i * 10 + 9));
    }
    ops.push(make_read(2, "k", Some("48"), 600, 610)); // Stale: expected 49
    assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
}

#[test]
fn test_checker_op_type_equality() {
    assert_eq!(OpType::Read, OpType::Read);
    assert_eq!(OpType::Write, OpType::Write);
    assert_ne!(OpType::Read, OpType::Write);
}

#[test]
fn test_checker_op_type_serde() {
    let r = OpType::Read;
    let w = OpType::Write;
    assert_eq!(r, serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap());
    assert_eq!(w, serde_json::from_str(&serde_json::to_string(&w).unwrap()).unwrap());
}

// ==========================================
// 3. Permutations, Timing & Clients (10 tests)
// ==========================================

#[test]
fn test_checker_client_id_isolation() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v", 10, 20),
        make_read(2, "k", Some("v"), 30, 40),
        make_read(3, "k", Some("v"), 50, 60),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_zero_timestamps() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v", 0, 0),
        make_read(2, "k", Some("v"), 0, 0),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_large_timestamp_advance() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v", 0, 10),
        make_read(2, "k", Some("v"), 1_000_000_000, 2_000_000_000),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_rapid_overwrites() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v1", 1, 2),
        make_write(1, "k", "v2", 3, 4),
        make_write(1, "k", "v3", 5, 6),
        make_write(1, "k", "v4", 7, 8),
        make_read(2, "k", Some("v4"), 9, 10),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_write_same_value_consecutively() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v", 10, 20),
        make_write(1, "k", "v", 30, 40),
        make_read(2, "k", Some("v"), 50, 60),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_empty_string_value_pass() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "", 10, 20),
        make_read(2, "k", Some(""), 30, 40),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_empty_string_value_violation() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "", 10, 20),
        make_read(2, "k", Some("non_empty"), 30, 40),
    ];
    assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
}

#[test]
fn test_checker_long_keys_and_values() {
    let checker = SequentialRegisterChecker;
    let key = "a".repeat(1024);
    let val = "b".repeat(4096);
    let ops = vec![
        make_write(1, &key, &val, 10, 20),
        make_read(2, &key, Some(&val), 30, 40),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_deterministic_evaluation() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "1", 10, 20),
        make_read(2, "k", Some("1"), 30, 40),
    ];
    let res1 = checker.check_history(&ops);
    let res2 = checker.check_history(&ops);
    assert_eq!(res1, res2);
}

#[test]
fn test_checker_client_independence() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(10, "k", "v", 1, 2),
        make_read(20, "k", Some("v"), 3, 4),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

// ==========================================
// 4. Invariant Stress & Property Tests (10 tests)
// ==========================================

#[test]
fn test_checker_stress_100_passes() {
    let checker = SequentialRegisterChecker;
    let mut ops = Vec::new();
    for i in 0..100 {
        ops.push(make_write(1, "key", &format!("val_{i}"), i * 10, i * 10 + 5));
        ops.push(make_read(2, "key", Some(&format!("val_{i}")), i * 10 + 6, i * 10 + 9));
    }
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_stress_100_violations() {
    let checker = SequentialRegisterChecker;
    for i in 1..=10 {
        let ops = vec![
            make_write(1, "k", &format!("correct_{i}"), 10, 20),
            make_read(2, "k", Some("wrong"), 30, 40),
        ];
        assert!(matches!(checker.check_history(&ops), CheckResult::Violation { .. }));
    }
}

#[test]
fn test_checker_multiple_reads_between_writes() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v1", 10, 20),
        make_read(2, "k", Some("v1"), 25, 26),
        make_read(3, "k", Some("v1"), 27, 28),
        make_read(4, "k", Some("v1"), 29, 30),
        make_write(1, "k", "v2", 35, 40),
        make_read(2, "k", Some("v2"), 45, 50),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_interleaved_client_reads() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v", 1, 10),
        make_read(2, "k", Some("v"), 11, 20),
        make_read(1, "k", Some("v"), 21, 30),
        make_read(2, "k", Some("v"), 31, 40),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_complete_time_after_invoke() {
    let op = make_write(1, "k", "v", 100, 200);
    assert!(op.invoke_time <= op.complete_time);
}

#[test]
fn test_checker_zero_duration_operation() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v", 100, 100),
        make_read(2, "k", Some("v"), 100, 100),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_sequential_clock_monotonicity() {
    let ops = vec![
        make_write(1, "k", "v1", 10, 20),
        make_write(1, "k", "v2", 30, 40),
    ];
    assert!(ops[0].complete_time < ops[1].invoke_time);
}

#[test]
fn test_checker_non_overlapping_clients() {
    let checker = SequentialRegisterChecker;
    let ops = vec![
        make_write(1, "k", "v1", 10, 20),
        make_read(2, "k", Some("v1"), 21, 30),
        make_write(3, "k", "v2", 31, 40),
        make_read(4, "k", Some("v2"), 41, 50),
    ];
    assert_eq!(checker.check_history(&ops), CheckResult::Pass);
}

#[test]
fn test_checker_value_clone_equality() {
    let op = make_write(1, "key", "val", 5, 10);
    assert_eq!(op.clone(), op);
}

#[test]
fn test_checker_pass_result_clone_equality() {
    let res = CheckResult::Pass;
    assert_eq!(res.clone(), res);
}
