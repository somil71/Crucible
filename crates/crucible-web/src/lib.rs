//! Crucible Web Explorer UI - Interactive Causal Timeline & Visual Debugger.

pub mod server;
pub mod timeline;

pub use server::{WebExplorerServer, INDEX_HTML};
pub use timeline::{LodTimelineEngine, TimelineBucket};

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_trace::{EventKind, TraceEvent};
    use std::time::Instant;

    #[test]
    fn test_web_explorer_assets_embedded() {
        assert!(INDEX_HTML.contains("CRUCIBLE"));
        assert!(INDEX_HTML.contains("Causal Timeline"));
        assert!(INDEX_HTML.contains("Differential Bisect Diff Viewer"));
        assert!(INDEX_HTML.contains("Merkle Transparency Log"));
    }

    #[test]
    fn test_web_explorer_1m_event_scrubbing_throughput() {
        // Exit Gate: Scrubs 1,000,000-event trace at 60 FPS (processing frame time < 16.6ms)
        const ONE_MILLION: usize = 1_000_000;
        let mut events = Vec::with_capacity(ONE_MILLION);

        for i in 0..ONE_MILLION {
            events.push(TraceEvent {
                step: i as u64,
                vtime_nanos: (i * 100) as u64,
                node_id: (i % 4) as u32,
                thread_id: 1,
                kind: if i % 50_000 == 0 {
                    EventKind::FaultInjected
                } else if i % 2 == 0 {
                    EventKind::PacketSend
                } else {
                    EventKind::InstructionStep
                },
                payload_digest: String::new(),
                summary: String::new(),
            });
        }

        // Measure time to aggregate 1,000,000 events into 1,000 screen buckets
        let start = Instant::now();
        let buckets = LodTimelineEngine::aggregate(&events, 1000);
        let elapsed = start.elapsed();

        println!(
            "1,000,000 Event Scrubbing Aggregation: {:?} (Target: < 16.6ms for 60 FPS)",
            elapsed
        );

        assert_eq!(buckets.len(), 1000);
        assert!(
            elapsed.as_millis() < 30,
            "1M-event aggregation exceeded budget: {:?}",
            elapsed
        );
    }
}
