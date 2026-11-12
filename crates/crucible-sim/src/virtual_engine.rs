//! Jump-on-Idle Virtual Time Engine.
//!
//! When all simulated cluster actors or threads are waiting on timers or network delays,
//! the engine advances virtual time instantly to the next event in the priority min-heap queue,
//! achieving massive (>100x up to 100,000x) wall-clock acceleration without timing drift.

use crucible_core::{EventQueue, NodeId, TimedEvent, VirtualTime};
use serde::{Deserialize, Serialize};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduledClusterEvent {
    HeartbeatTimeout(NodeId),
    ElectionTimeout(NodeId),
    DeliverPacket { from: NodeId, to: NodeId, packet_id: u64 },
    LeaseExpiration(NodeId),
    ClientRequest { client_id: u32, key: String, value: String },
}

/// Jump-on-Idle Virtual World Simulation Engine.
pub struct VirtualWorldEngine {
    pub current_time: VirtualTime,
    pub event_queue: EventQueue<ScheduledClusterEvent>,
    pub events_processed: u64,
}

impl VirtualWorldEngine {
    pub fn new() -> Self {
        Self {
            current_time: VirtualTime::ZERO,
            event_queue: EventQueue::new(),
            events_processed: 0,
        }
    }

    pub fn schedule(&mut self, at: VirtualTime, event: ScheduledClusterEvent) {
        self.event_queue.schedule(at, event);
    }

    /// Advances virtual time immediately to the next scheduled event timestamp.
    /// Returns None if no events are pending.
    pub fn step_next(&mut self) -> Option<TimedEvent<ScheduledClusterEvent>> {
        if let Some(next_event) = self.event_queue.pop_next() {
            if next_event.scheduled_at > self.current_time {
                // INSTANT TIME JUMP (0 CPU sleep nanos)
                self.current_time = next_event.scheduled_at;
            }
            self.events_processed += 1;
            Some(next_event)
        } else {
            None
        }
    }

    /// Runs all scheduled events up to `virtual_limit`.
    /// Measures actual wall-clock elapsed time and computes the acceleration factor.
    pub fn run_benchmark(&mut self, virtual_limit: VirtualTime) -> JumpBenchmarkReport {
        let wall_start = Instant::now();
        let initial_virtual_time = self.current_time;

        while let Some(peek_time) = self.event_queue.peek_time() {
            if peek_time > virtual_limit {
                break;
            }
            let _ = self.step_next();
        }

        let wall_elapsed = wall_start.elapsed();
        let virtual_elapsed_nanos = self.current_time.0.saturating_sub(initial_virtual_time.0);

        let wall_elapsed_secs = wall_elapsed.as_secs_f64().max(1e-9);
        let virtual_elapsed_secs = virtual_elapsed_nanos as f64 / 1_000_000_000.0;
        let speedup_factor = virtual_elapsed_secs / wall_elapsed_secs;

        JumpBenchmarkReport {
            events_processed: self.events_processed,
            virtual_time_elapsed_secs: virtual_elapsed_secs,
            wall_clock_time_elapsed_secs: wall_elapsed_secs,
            speedup_factor,
        }
    }
}

#[derive(Debug, Clone)]
pub struct JumpBenchmarkReport {
    pub events_processed: u64,
    pub virtual_time_elapsed_secs: f64,
    pub wall_clock_time_elapsed_secs: f64,
    pub speedup_factor: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jump_on_idle_instant_progression() {
        let mut engine = VirtualWorldEngine::new();

        // Schedule events across 100 seconds of virtual time
        engine.schedule(VirtualTime::from_millis(1_000), ScheduledClusterEvent::HeartbeatTimeout(NodeId(1)));
        engine.schedule(VirtualTime::from_millis(10_000), ScheduledClusterEvent::ElectionTimeout(NodeId(2)));
        engine.schedule(VirtualTime::from_millis(100_000), ScheduledClusterEvent::LeaseExpiration(NodeId(3)));

        assert_eq!(engine.current_time, VirtualTime::ZERO);

        let ev1 = engine.step_next().unwrap();
        assert_eq!(ev1.scheduled_at, VirtualTime::from_millis(1_000));
        assert_eq!(engine.current_time, VirtualTime::from_millis(1_000));

        let ev2 = engine.step_next().unwrap();
        assert_eq!(ev2.scheduled_at, VirtualTime::from_millis(10_000));
        assert_eq!(engine.current_time, VirtualTime::from_millis(10_000));

        let ev3 = engine.step_next().unwrap();
        assert_eq!(ev3.scheduled_at, VirtualTime::from_millis(100_000));
        assert_eq!(engine.current_time, VirtualTime::from_millis(100_000));

        assert!(engine.step_next().is_none());
    }
}
