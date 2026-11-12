//! Claim CLM-002: Jump-on-Idle Speedup Certification Test.
//!
//! Statement: Virtual time advances instantly to the next scheduled event when all threads
//! or actors are blocked, achieving >100x wall-clock speedup during idle timeouts.

use crucible_core::{NodeId, VirtualTime};
use crucible_sim::{ScheduledClusterEvent, VirtualWorldEngine};

#[test]
fn test_clm_002_jump_on_idle_speedup_benchmark() {
    println!("\n============================================================");
    println!("CLAIM CLM-002: JUMP-ON-IDLE SPEEDUP CERTIFICATION");
    println!("============================================================");

    let mut engine = VirtualWorldEngine::new();
    let total_virtual_duration_secs = 600.0; // 10 minutes of simulated distributed time
    let total_virtual_nanos = (total_virtual_duration_secs * 1_000_000_000.0) as u64;

    // Schedule 10 minutes of distributed heartbeats (every 100ms),
    // election timers (every 1000ms), and client requests (every 2500ms) across 3 nodes.
    let mut t = 0u64;
    let mut packet_counter = 0u64;
    while t < total_virtual_nanos {
        t += 100_000_000; // +100ms
        engine.schedule(
            VirtualTime(t),
            ScheduledClusterEvent::HeartbeatTimeout(NodeId(1)),
        );

        if t % 1_000_000_000 == 0 {
            engine.schedule(
                VirtualTime(t),
                ScheduledClusterEvent::ElectionTimeout(NodeId(2)),
            );
        }

        if t % 2_500_000_000 == 0 {
            packet_counter += 1;
            engine.schedule(
                VirtualTime(t),
                ScheduledClusterEvent::DeliverPacket {
                    from: NodeId(1),
                    to: NodeId(3),
                    packet_id: packet_counter,
                },
            );
        }
    }

    println!("Total scheduled timed events in queue: {}", engine.event_queue.peek_time().is_some());

    // Execute through the Jump-on-Idle engine
    let report = engine.run_benchmark(VirtualTime(total_virtual_nanos));

    println!("------------------------------------------------------------");
    println!("JUMP-ON-IDLE EMPIRICAL RESULTS:");
    println!("  Total Events Processed:        {}", report.events_processed);
    println!("  Virtual Time Elapsed:          {:.2} seconds ({:.1} minutes)",
             report.virtual_time_elapsed_secs, report.virtual_time_elapsed_secs / 60.0);
    println!("  Actual Wall-Clock Time:        {:.6} seconds", report.wall_clock_time_elapsed_secs);
    println!("  Empirical Speedup Factor:      {:.2}x", report.speedup_factor);
    println!("  Required Minimum (CLM-002):    100.00x");
    println!("------------------------------------------------------------");

    // Must exceed 100x speedup threshold required by CLM-002
    assert!(
        report.speedup_factor >= 100.0,
        "Speedup factor {:.2}x was below required 100.0x threshold",
        report.speedup_factor
    );
    assert!(
        report.events_processed > 5000,
        "Expected >5000 events processed, got {}",
        report.events_processed
    );

    println!("============================================================");
    println!("CLAIM CLM-002 CERTIFIED: Speedup {:.2}x exceeds threshold >= 100x.", report.speedup_factor);
    println!("============================================================\n");
}
