//! Spike 4: Historical Bug Reproduction & Fault Schedule Minimization.
//!
//! Objectives:
//! 1. Reproduce historical Raft Figure 8 uncommitted log overwrite bug (§5.4.2).
//! 2. Automated minimization of a noisy fault schedule (15 faults) to a minimal causal schedule (<= 5 events).
//! 3. Verify Linearizability Checker violation on buggy engine and clean pass on fixed engine.

use crucible_checkers::CheckResult;
use crucible_core::{DeltaDebugger, NodeId};
use crucible_sim::{execute_history_schedule, HistoryFault};

#[test]
fn test_spike4_historical_raft_bug_and_minimization() {
    println!("\n============================================================");
    println!("SPIKE 4: HISTORICAL RAFT BUG REPRODUCTION & MINIMIZATION");
    println!("============================================================");

    // Construct a realistic noisy exploration schedule containing 15 faults:
    // 5 critical causal faults + 10 benign/extraneous noise events.
    let full_noisy_schedule: Vec<HistoryFault> = vec![
        HistoryFault::BenignDelayPacket(NodeId(2), NodeId(4)),
        HistoryFault::BenignClockSkew(NodeId(4), 1200),
        HistoryFault::BenignIsolateNode(NodeId(2)),
        // Critical 1: Isolate Leader 1
        HistoryFault::IsolateNode(NodeId(1)),
        HistoryFault::BenignTornWrite(NodeId(4), 99),
        // Critical 2: Elect Node 5 in Term 3 (writes "x"="v2")
        HistoryFault::ElectLeader {
            candidate: NodeId(5),
            term: 3,
            electors: vec![NodeId(3), NodeId(4), NodeId(5)],
        },
        HistoryFault::BenignDelayPacket(NodeId(3), NodeId(4)),
        // Critical 3: Crash Node 5 before replication
        HistoryFault::CrashNode(NodeId(5)),
        HistoryFault::BenignClockSkew(NodeId(3), -400),
        // Critical 4: Reconnect Node 1, elect in Term 4 (replicates Term 2 entry to Node 3)
        HistoryFault::ReconnectNode(NodeId(1)),
        HistoryFault::ElectLeader {
            candidate: NodeId(1),
            term: 4,
            electors: vec![NodeId(1), NodeId(2), NodeId(3)],
        },
        HistoryFault::BenignTornWrite(NodeId(4), 101),
        HistoryFault::BenignHeal(NodeId(2)),
        // Critical 5: Crash Node 1, recover Node 5, elect in Term 5 (overwrites Node 3!)
        HistoryFault::CrashNode(NodeId(1)),
        HistoryFault::RecoverNode(NodeId(5)),
        HistoryFault::ElectLeader {
            candidate: NodeId(5),
            term: 5,
            electors: vec![NodeId(3), NodeId(4), NodeId(5)],
        },
    ];

    assert_eq!(full_noisy_schedule.len(), 16);
    println!("Initial un-minimized fault schedule length: {} events", full_noisy_schedule.len());

    // 1. Verify that the initial noisy schedule triggers the linearizability violation
    let (initial_result, history) = execute_history_schedule(&full_noisy_schedule, true);
    match &initial_result {
        CheckResult::Violation { description, .. } => {
            println!("Initial run reproduced violation: {}", description);
        }
        CheckResult::Pass => {
            panic!("Expected initial noisy schedule to trigger linearizability violation");
        }
    }
    println!("Total recorded KV operations: {}", history.len());

    // 2. Automated delta-debugging minimization to shrink fault schedule
    let predicate = |faults: &[HistoryFault]| {
        let (result, _) = execute_history_schedule(faults, true);
        matches!(result, CheckResult::Violation { .. })
    };

    let minimized_schedule = DeltaDebugger::minimize(&full_noisy_schedule, predicate);
    println!("\nAutomated Delta-Debugging complete!");
    println!("Minimized fault schedule length: {} events", minimized_schedule.len());
    for (i, fault) in minimized_schedule.iter().enumerate() {
        println!("  Fault #{}: {:?}", i + 1, fault);
    }

    // Pass Criteria Check: Minimized schedule must be <= 5 events
    assert!(
        minimized_schedule.len() <= 5,
        "Minimized schedule had {} events, expected <= 5 events",
        minimized_schedule.len()
    );

    // 3. Verify that replaying the minimized schedule alone reproduces the exact violation
    let (minimized_result, min_history) = execute_history_schedule(&minimized_schedule, true);
    match &minimized_result {
        CheckResult::Violation { description, .. } => {
            println!("\nMinimized schedule verified violation: {}", description);
            assert!(description.contains("Stale read detected for key x"));
        }
        CheckResult::Pass => {
            panic!("Minimized schedule failed to reproduce linearizability violation");
        }
    }
    println!("Minimized history operations: {}", min_history.len());

    // 4. Counterfactual verification: Under the fixed engine (§5.4.2), the violation disappears
    let (fixed_result, _) = execute_history_schedule(&minimized_schedule, false);
    assert_eq!(
        fixed_result,
        CheckResult::Pass,
        "Fixed Raft engine (§5.4.2) must pass without linearizability violation"
    );
    println!("Counterfactual test passed: Fixed Raft engine safely passed without violation.");
    println!("============================================================");
    println!("SPIKE 4 PASSED: Linearizability bug reproduced and minimized to <= 5 events.");
    println!("============================================================\n");
}
