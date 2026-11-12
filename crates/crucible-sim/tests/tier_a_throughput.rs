//! Phase 1 Exit Gate Benchmark: Pure Tier A Simulation Throughput.
//!
//! Requirement: 3-node Raft test suite runs at >100,000 simulated events/sec.

use crucible_core::NodeId;
use crucible_sim::{ClusterAction, RaftCluster};
use std::time::Instant;

#[test]
fn test_tier_a_raft_3node_throughput_benchmark() {
    println!("\n============================================================");
    println!("PHASE 1 BENCHMARK: TIER A RAFT SIMULATION THROUGHPUT");
    println!("============================================================");

    let mut cluster = RaftCluster::new_3node_cluster(false);
    let leader = NodeId(1);

    // 1. Elect Node 1 as leader
    cluster.step_action(ClusterAction::TriggerElection(leader));
    while !cluster.network.in_flight.is_empty() {
        cluster.step_action(ClusterAction::DeliverPacket);
    }
    assert_eq!(cluster.nodes[&leader].role, crucible_sim::Role::Leader);
    println!("Leader elected successfully: Node 1 in Term {}", cluster.nodes[&leader].current_term);

    // 2. High-throughput event processing loop
    let target_proposals = 30_000;
    let mut total_simulated_events = 0u64;

    let start_wall = Instant::now();

    for i in 1..=target_proposals {
        let val = format!("val_{}", i);
        cluster.step_action(ClusterAction::ProposeCommand(leader, val));
        total_simulated_events += 1;

        // Drain all generated replication packets
        while !cluster.network.in_flight.is_empty() {
            cluster.step_action(ClusterAction::DeliverPacket);
            total_simulated_events += 1;
        }
    }

    let elapsed = start_wall.elapsed();
    let elapsed_secs = elapsed.as_secs_f64().max(1e-9);
    let events_per_sec = total_simulated_events as f64 / elapsed_secs;

    // Flush final commit index to followers via heartbeat
    let final_commit = cluster.nodes[&leader].commit_index;
    for peer in [NodeId(2), NodeId(3)] {
        cluster.network.send(
            cluster.current_time,
            leader,
            peer,
            crucible_sim::RaftMessage::AppendEntries {
                term: cluster.nodes[&leader].current_term,
                leader_id: leader,
                prev_log_index: target_proposals,
                prev_log_term: cluster.nodes[&leader].current_term,
                entries: Vec::new(),
                leader_commit: final_commit,
            },
        );
    }
    while !cluster.network.in_flight.is_empty() {
        cluster.step_action(ClusterAction::DeliverPacket);
    }

    println!("------------------------------------------------------------");
    println!("TIER A THROUGHPUT EMPIRICAL METRICS:");
    println!("  Total Commands Proposed:        {}", target_proposals);
    println!("  Total Simulated Events:         {}", total_simulated_events);
    println!("  Wall-Clock Elapsed Time:        {:.4} seconds", elapsed_secs);
    println!("  Throughput (Events / Sec):      {:.2} events/sec", events_per_sec);
    println!("  Required Minimum Exit Gate:     100,000.00 events/sec");
    println!("------------------------------------------------------------");

    // Verify all nodes committed up to the last proposal
    assert_eq!(cluster.nodes[&leader].commit_index, target_proposals);
    assert_eq!(cluster.nodes[&NodeId(2)].commit_index, target_proposals);
    assert_eq!(cluster.nodes[&NodeId(3)].commit_index, target_proposals);

    // Must satisfy the Phase 1 exit gate threshold: > 100,000 events/sec
    assert!(
        events_per_sec >= 100_000.0,
        "Throughput {:.2} events/sec was below the required 100,000.0 events/sec gate",
        events_per_sec
    );

    println!("============================================================");
    println!("PHASE 1 GATE PASSED: Pure Tier A runs at {:.2} events/sec (> 100,000).", events_per_sec);
    println!("============================================================\n");
}
