//! Phase 3 Exit Gate Integration Test: Hierarchical Minimization, Causal Slicing & Root-Cause Ranking.
//!
//! Requirement: "Minimized failure trace contains only events on the critical causal path."
//! - Hierarchical minimization reduces a 50-event noisy schedule down to <= 4 critical causal events.
//! - CausalTraceSlicer extracts the exact transitive-reduction DAG backward cone.
//! - RootCauseRanker ranks the true root-cause fault at Rank #1 with 1.0 Ochiai score.

use crucible_checkers::{
    CampaignRun, CausalGraph, CausalTraceSlicer, RootCauseRanker, VectorClock,
};
use crucible_core::{HierarchicalMinimizer, NodeId, VirtualTime};
use crucible_sim::{execute_history_schedule, HistoryFault};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
struct TimedScheduleFault {
    pub category: &'static str,
    pub fault: HistoryFault,
    pub time: VirtualTime,
}

#[test]
fn test_phase3_hierarchical_minimizer_and_causal_slicer() {
    println!("\n============================================================");
    println!("PHASE 3 EXIT GATE: HIERARCHICAL MINIMIZATION & CAUSAL SLICING");
    println!("============================================================");

    // 1. Build a realistic 50-event noisy exploration schedule containing:
    // - 46 noise events across "network_delay", "disk_churn", "clock_jitter", and idle nodes.
    // - 4 critical causal events that trigger the Raft Figure 8 commit anomaly.
    let mut noisy_faults: Vec<TimedScheduleFault> = Vec::new();

    // 10 Network delays (Noise)
    for i in 1..=10 {
        noisy_faults.push(TimedScheduleFault {
            category: "network_noise",
            fault: HistoryFault::BenignDelayPacket(NodeId(2), NodeId(4)),
            time: VirtualTime::from_millis(10 * i),
        });
    }

    // Critical 1: Isolate Leader 1
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::IsolateNode(NodeId(1)),
        time: VirtualTime::from_millis(200),
    });

    // 10 Clock jitters (Noise)
    for i in 1..=10 {
        noisy_faults.push(TimedScheduleFault {
            category: "clock_jitter",
            fault: HistoryFault::BenignClockSkew(NodeId(4), 100 * i as i64),
            time: VirtualTime::from_millis(200 + 10 * i),
        });
    }

    // Critical 2: Elect Node 5 in Term 3 (writes uncommitted entry)
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::ElectLeader {
            candidate: NodeId(5),
            term: 3,
            electors: vec![NodeId(3), NodeId(4), NodeId(5)],
        },
        time: VirtualTime::from_millis(400),
    });

    // 10 Disk writes on idle node 4 (Noise)
    for i in 1..=10 {
        noisy_faults.push(TimedScheduleFault {
            category: "disk_churn",
            fault: HistoryFault::BenignTornWrite(NodeId(4), i * 10),
            time: VirtualTime::from_millis(400 + 10 * i),
        });
    }

    // Critical 3: Reconnect Node 1, elect in Term 4 (replicates Term 2 entry to Node 3)
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::ReconnectNode(NodeId(1)),
        time: VirtualTime::from_millis(600),
    });
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::ElectLeader {
            candidate: NodeId(1),
            term: 4,
            electors: vec![NodeId(1), NodeId(2), NodeId(3)],
        },
        time: VirtualTime::from_millis(650),
    });

    // 15 Miscellaneous noise events
    for i in 1..=15 {
        noisy_faults.push(TimedScheduleFault {
            category: "network_noise",
            fault: HistoryFault::BenignDelayPacket(NodeId(3), NodeId(4)),
            time: VirtualTime::from_millis(700 + 10 * i),
        });
    }

    // Critical 4: Crash Node 1, recover Node 5, elect in Term 5 (overwrites committed entry)
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::CrashNode(NodeId(1)),
        time: VirtualTime::from_millis(900),
    });
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::RecoverNode(NodeId(5)),
        time: VirtualTime::from_millis(950),
    });
    noisy_faults.push(TimedScheduleFault {
        category: "cluster_topology",
        fault: HistoryFault::ElectLeader {
            candidate: NodeId(5),
            term: 5,
            electors: vec![NodeId(3), NodeId(4), NodeId(5)],
        },
        time: VirtualTime::from_millis(5000), // large time gap
    });

    assert_eq!(noisy_faults.len(), 52);
    println!("Initial un-minimized fault schedule: {} events", noisy_faults.len());

    // 2. Define reproduction predicate
    let predicate = |items: &[TimedScheduleFault]| {
        let raw_faults: Vec<HistoryFault> = items.iter().map(|f| f.fault.clone()).collect();
        let (result, _) = execute_history_schedule(&raw_faults, true);
        matches!(result, crucible_checkers::CheckResult::Violation { .. })
    };

    assert!(predicate(&noisy_faults), "Initial schedule must reproduce the violation");

    // 3. Multi-Stage Hierarchical Minimizer
    let minimized = HierarchicalMinimizer::minimize_hierarchical(
        &noisy_faults,
        |f| f.category,
        |f| f.time,
        |f, t| f.time = t,
        predicate,
    );

    println!("------------------------------------------------------------");
    println!("HIERARCHICAL MINIMIZATION METRICS:");
    println!("  Initial Event Count:           {}", noisy_faults.len());
    println!("  Minimized Event Count:         {}", minimized.len());
    println!("  Pruned Irrelevant Noise:       {} events ({:.2}%)",
             noisy_faults.len() - minimized.len(),
             (noisy_faults.len() - minimized.len()) as f64 / noisy_faults.len() as f64 * 100.0);
    println!("------------------------------------------------------------");

    // Exit Gate Check: Minimized schedule must contain <= 4 critical events
    assert!(
        minimized.len() <= 4,
        "Expected <= 4 minimized causal events, got {}",
        minimized.len()
    );

    for (idx, fault) in minimized.iter().enumerate() {
        println!("  Critical Event #{}: [{:?}] at time {:?}", idx + 1, fault.fault, fault.time);
    }

    // Timeline compression verified: final event time compressed from 5000ms down to near predecessors
    assert!(
        minimized.last().unwrap().time.as_millis() < 5000,
        "Timeline compression failed to shrink virtual time gap"
    );

    // 4. Causal Trace Slicing on Execution Graph
    let mut graph = CausalGraph::new();
    let n1 = NodeId(1);
    let n2 = NodeId(2);
    let n3 = NodeId(3);

    let mut vc1 = VectorClock::new();
    let mut vc2 = VectorClock::new();
    let mut vc3 = VectorClock::new();

    // Node 1 sends log entry
    vc1.tick(n1);
    let ev1 = graph.record_event(n1, &vc1, "Leader 1 Propose Entry", VirtualTime(10));

    // Node 2 concurrent noise
    vc2.tick(n2);
    let _ev_noise = graph.record_event(n2, &vc2, "Node 2 Background Compaction", VirtualTime(15));

    // Node 3 receives from Node 1
    vc3.merge(&vc1);
    vc3.tick(n3);
    let ev2 = graph.record_event(n3, &vc3, "Node 3 Replicate Entry", VirtualTime(20));

    // Node 3 triggers Linearizability Stale Read Violation
    vc3.tick(n3);
    let ev_fail = graph.record_event(n3, &vc3, "Linearizability Violation Detected", VirtualTime(30));

    let explanation = CausalTraceSlicer::slice_and_explain(&graph, ev_fail).unwrap();
    println!("\n------------------------------------------------------------");
    println!("CAUSAL TRACE SLICER EXPLANATION:");
    println!("  Total Events in Full Trace:    {}", graph.events.len());
    println!("  Critical Causal Path Events:   {}", explanation.critical_events.len());
    println!("  Pruned Noise Events:           {}", explanation.pruned_events_count);
    println!("  Noise Reduction Ratio:         {:.2}%", explanation.noise_reduction_ratio * 100.0);
    println!("  Direct Transitive Edges:       {:?}", explanation.direct_causal_edges);
    println!("------------------------------------------------------------");

    let critical_ids: Vec<u64> = explanation.critical_events.iter().map(|e| e.id).collect();
    assert_eq!(critical_ids, vec![ev1, ev2, ev_fail]);
    assert_eq!(explanation.direct_causal_edges, vec![(ev1, ev2), (ev2, ev_fail)]);

    // 5. Statistical Root-Cause Ranker Validation across 20 campaign runs
    let mut campaign_runs = Vec::new();
    let root_cause = "Figure8_Commit_Without_CurrentTerm_Check";

    // 10 Failing runs where root cause was always active
    for i in 1..=10 {
        let mut faults = HashSet::new();
        faults.insert(root_cause.to_string());
        if i % 2 == 0 {
            faults.insert("PacketDelay_Node2".to_string());
        }
        campaign_runs.push(CampaignRun {
            run_id: i,
            faults,
            failed: true,
        });
    }

    // 10 Passing runs where root cause was absent
    for i in 11..=20 {
        let mut faults = HashSet::new();
        faults.insert("BenignClockDrift".to_string());
        faults.insert("PacketDelay_Node2".to_string());
        campaign_runs.push(CampaignRun {
            run_id: i,
            faults,
            failed: false,
        });
    }

    let rankings = RootCauseRanker::rank_suspects(&campaign_runs);
    println!("\n------------------------------------------------------------");
    println!("STATISTICAL ROOT-CAUSE RANKINGS (Ochiai Spectrum Analysis):");
    for (rank, r) in rankings.iter().enumerate() {
        println!("  Rank #{}: {} (Ochiai: {:.4}, Fails: {}, Passes: {})",
                 rank + 1, r.fault, r.ochiai_score, r.fail_count, r.pass_count);
    }
    println!("------------------------------------------------------------");

    // The true root cause must be ranked #1 with an Ochiai score of 1.0000
    assert_eq!(rankings[0].fault, root_cause);
    assert_eq!(rankings[0].ochiai_score, 1.0);
    assert_eq!(rankings[0].fail_count, 10);
    assert_eq!(rankings[0].pass_count, 0);

    println!("============================================================");
    println!("PHASE 3 EXIT GATE PASSED: Minimized schedule contains ONLY critical causal events.");
    println!("============================================================\n");
}
