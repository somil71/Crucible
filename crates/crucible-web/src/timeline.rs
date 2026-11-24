//! Virtualized Timeline Level-of-Detail (LOD) Engine.

use crucible_trace::{EventKind, TraceEvent};

/// Aggregated density bucket for rendering 1,000,000-event timelines without GPU memory stalls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineBucket {
    pub start_step: u64,
    pub end_step: u64,
    pub node_id: u32,
    pub event_count: usize,
    pub dominant_kind: EventKind,
    pub has_fault: bool,
}

/// Level of Detail (LOD) timeline aggregator.
pub struct LodTimelineEngine;

impl LodTimelineEngine {
    /// Aggregates an arbitrary number of events (up to 1,000,000+) into a fixed number of screen pixel buckets.
    pub fn aggregate(events: &[TraceEvent], bucket_count: usize) -> Vec<TimelineBucket> {
        if events.is_empty() || bucket_count == 0 {
            return Vec::new();
        }

        let chunk_size = ((events.len() as f64) / (bucket_count as f64)).ceil() as usize;
        let mut buckets = Vec::with_capacity(bucket_count);

        for chunk in events.chunks(chunk_size) {
            let start_step = chunk.first().map(|e| e.step).unwrap_or(0);
            let end_step = chunk.last().map(|e| e.step).unwrap_or(0);
            let node_id = chunk.first().map(|e| e.node_id).unwrap_or(0);
            let event_count = chunk.len();
            let has_fault = chunk.iter().any(|e| e.kind == EventKind::FaultInjected);
            let dominant_kind = chunk
                .first()
                .map(|e| e.kind)
                .unwrap_or(EventKind::InstructionStep);

            buckets.push(TimelineBucket {
                start_step,
                end_step,
                node_id,
                event_count,
                dominant_kind,
                has_fault,
            });
        }

        buckets
    }
}
