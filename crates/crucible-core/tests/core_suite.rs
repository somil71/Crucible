use crucible_core::{
    compute_trace_hash, EventQueue, FaultAction, FaultSchedule, NodeId, ScheduledFault, Seed,
    ThreadId, VirtualTime,
};

// ==========================================
// 1. VirtualTime Tests (10 tests)
// ==========================================

#[test]
fn test_vtime_zero() {
    assert_eq!(VirtualTime::ZERO.0, 0);
    assert_eq!(VirtualTime::ZERO.as_millis(), 0);
}

#[test]
fn test_vtime_from_millis() {
    let t = VirtualTime::from_millis(50);
    assert_eq!(t.0, 50_000_000);
    assert_eq!(t.as_millis(), 50);
}

#[test]
fn test_vtime_advance() {
    let mut t = VirtualTime(100);
    t.advance_by(500);
    assert_eq!(t.0, 600);
}

#[test]
fn test_vtime_ordering() {
    let t1 = VirtualTime(100);
    let t2 = VirtualTime(200);
    assert!(t1 < t2);
    assert!(t2 > t1);
    assert_eq!(t1, VirtualTime(100));
}

#[test]
fn test_vtime_large_values() {
    let t = VirtualTime::from_millis(1_000_000);
    assert_eq!(t.as_millis(), 1_000_000);
}

#[test]
fn test_vtime_default() {
    let t: VirtualTime = Default::default();
    assert_eq!(t, VirtualTime::ZERO);
}

#[test]
fn test_vtime_serialization() {
    let t = VirtualTime(123456789);
    let json = serde_json::to_string(&t).unwrap();
    let deser: VirtualTime = serde_json::from_str(&json).unwrap();
    assert_eq!(t, deser);
}

#[test]
fn test_vtime_advance_zero() {
    let mut t = VirtualTime(42);
    t.advance_by(0);
    assert_eq!(t.0, 42);
}

#[test]
fn test_vtime_millis_rounding() {
    let t = VirtualTime(1_999_999);
    assert_eq!(t.as_millis(), 1);
}

#[test]
fn test_vtime_nanos_boundary() {
    let t = VirtualTime(u64::MAX);
    assert_eq!(t.0, u64::MAX);
}

// ==========================================
// 2. EventQueue Priority & Monotonicity (10 tests)
// ==========================================

#[test]
fn test_event_queue_empty_peek() {
    let q: EventQueue<u32> = EventQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.peek_time(), None);
}

#[test]
fn test_event_queue_single_item() {
    let mut q = EventQueue::new();
    q.schedule(VirtualTime(10), 100);
    assert!(!q.is_empty());
    assert_eq!(q.peek_time(), Some(VirtualTime(10)));
    let item = q.pop_next().unwrap();
    assert_eq!(item.payload, 100);
    assert!(q.is_empty());
}

#[test]
fn test_event_queue_fifo_order_on_same_time() {
    let mut q = EventQueue::new();
    q.schedule(VirtualTime(100), "first");
    q.schedule(VirtualTime(100), "second");
    q.schedule(VirtualTime(100), "third");

    assert_eq!(q.pop_next().unwrap().payload, "first");
    assert_eq!(q.pop_next().unwrap().payload, "second");
    assert_eq!(q.pop_next().unwrap().payload, "third");
}

#[test]
fn test_event_queue_interleaved_timestamps() {
    let mut q = EventQueue::new();
    q.schedule(VirtualTime(500), 5);
    q.schedule(VirtualTime(100), 1);
    q.schedule(VirtualTime(300), 3);
    q.schedule(VirtualTime(200), 2);
    q.schedule(VirtualTime(400), 4);

    for expected in 1..=5 {
        assert_eq!(q.pop_next().unwrap().payload, expected);
    }
}

#[test]
fn test_event_queue_drain_to_empty() {
    let mut q = EventQueue::new();
    for i in 0..100 {
        q.schedule(VirtualTime(i), i);
    }
    assert!(!q.is_empty());
    for i in 0..100 {
        assert_eq!(q.pop_next().unwrap().payload, i);
    }
    assert!(q.is_empty());
    assert_eq!(q.pop_next(), None);
}

#[test]
fn test_event_queue_peek_does_not_consume() {
    let mut q = EventQueue::new();
    q.schedule(VirtualTime(50), 999);
    assert_eq!(q.peek_time(), Some(VirtualTime(50)));
    assert_eq!(q.peek_time(), Some(VirtualTime(50)));
    assert_eq!(q.pop_next().unwrap().payload, 999);
    assert_eq!(q.peek_time(), None);
}

#[test]
fn test_event_queue_monotonic_sequences() {
    let mut q = EventQueue::new();
    q.schedule(VirtualTime(10), "a");
    q.schedule(VirtualTime(10), "b");
    let e1 = q.pop_next().unwrap();
    let e2 = q.pop_next().unwrap();
    assert!(e1.sequence < e2.sequence);
}

#[test]
fn test_event_queue_large_batch() {
    let mut q = EventQueue::new();
    for i in (0..1000).rev() {
        q.schedule(VirtualTime(i), i);
    }
    let mut prev = 0;
    while let Some(e) = q.pop_next() {
        assert!(e.payload >= prev);
        prev = e.payload;
    }
}

#[test]
fn test_event_queue_time_jump() {
    let mut q = EventQueue::new();
    q.schedule(VirtualTime(1_000_000_000), "heartbeat");
    assert_eq!(q.peek_time().unwrap().0, 1_000_000_000);
}

#[test]
fn test_event_queue_default() {
    let mut q: EventQueue<i32> = Default::default();
    assert!(q.is_empty());
    q.schedule(VirtualTime(1), 1);
    assert_eq!(q.pop_next().unwrap().payload, 1);
}

// ==========================================
// 3. Fault DSL & Scheduling (10 tests)
// ==========================================

#[test]
fn test_fault_dsl_partition() {
    let fault = FaultAction::NetworkPartition {
        partition_a: vec![NodeId(1), NodeId(2)],
        partition_b: vec![NodeId(3)],
    };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_heal() {
    let fault = FaultAction::NetworkHeal;
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_packet_loss() {
    let fault = FaultAction::PacketLoss { rate: 0.25 };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_delay() {
    let fault = FaultAction::DelayPacket {
        from: NodeId(1),
        to: NodeId(2),
        delay_nanos: 50_000_000,
    };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_crash_node() {
    let fault = FaultAction::CrashNode { node: NodeId(3) };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_restart_with_disk() {
    let fault = FaultAction::RestartNode {
        node: NodeId(3),
        retain_disk: true,
    };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_restart_without_disk() {
    let fault = FaultAction::RestartNode {
        node: NodeId(2),
        retain_disk: false,
    };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_torn_write() {
    let fault = FaultAction::TornWriteDisk {
        node: NodeId(1),
        sector: 1024,
    };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_dsl_clock_skew() {
    let fault = FaultAction::ClockSkew {
        node: NodeId(2),
        offset_nanos: -500_000,
    };
    let json = serde_json::to_string(&fault).unwrap();
    let deser: FaultAction = serde_json::from_str(&json).unwrap();
    assert_eq!(fault, deser);
}

#[test]
fn test_fault_schedule_program() {
    let prog = FaultSchedule {
        seed: 42,
        faults: vec![
            ScheduledFault {
                trigger_time: VirtualTime(100),
                action: FaultAction::CrashNode { node: NodeId(1) },
            },
            ScheduledFault {
                trigger_time: VirtualTime(200),
                action: FaultAction::RestartNode {
                    node: NodeId(1),
                    retain_disk: true,
                },
            },
        ],
    };
    let json = serde_json::to_string_pretty(&prog).unwrap();
    let deser: FaultSchedule = serde_json::from_str(&json).unwrap();
    assert_eq!(prog, deser);
}

// ==========================================
// 4. Trace Hashing & Identifiers (10 tests)
// ==========================================

#[test]
fn test_trace_hash_empty() {
    let h1 = compute_trace_hash(b"");
    let h2 = compute_trace_hash(b"");
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 32]);
}

#[test]
fn test_trace_hash_avalanche() {
    let trace1 = b"deterministic execution log event 0000".to_vec();
    let mut trace2 = trace1.clone();
    let last_idx = trace2.len() - 1;
    trace2[last_idx] = b'1';

    let h1 = compute_trace_hash(&trace1);
    let h2 = compute_trace_hash(&trace2);
    assert_ne!(h1, h2);
}

#[test]
fn test_trace_hash_non_commutative() {
    let event_a = b"node1:recv:msg1;";
    let event_b = b"node2:send:msg2;";

    let mut trace_ab = Vec::new();
    trace_ab.extend_from_slice(event_a);
    trace_ab.extend_from_slice(event_b);

    let mut trace_ba = Vec::new();
    trace_ba.extend_from_slice(event_b);
    trace_ba.extend_from_slice(event_a);

    assert_ne!(compute_trace_hash(&trace_ab), compute_trace_hash(&trace_ba));
}

#[test]
fn test_seed_equality() {
    let s1 = Seed(12345);
    let s2 = Seed(12345);
    let s3 = Seed(54321);
    assert_eq!(s1, s2);
    assert_ne!(s1, s3);
}

#[test]
fn test_seed_serde() {
    let s = Seed(999999);
    let json = serde_json::to_string(&s).unwrap();
    let deser: Seed = serde_json::from_str(&json).unwrap();
    assert_eq!(s, deser);
}

#[test]
fn test_thread_id_ordering() {
    let t1 = ThreadId(1);
    let t2 = ThreadId(2);
    assert!(t1 < t2);
}

#[test]
fn test_thread_id_serde() {
    let t = ThreadId(42);
    let json = serde_json::to_string(&t).unwrap();
    let deser: ThreadId = serde_json::from_str(&json).unwrap();
    assert_eq!(t, deser);
}

#[test]
fn test_node_id_ordering() {
    let n1 = NodeId(1);
    let n2 = NodeId(2);
    assert!(n1 < n2);
}

#[test]
fn test_node_id_serde() {
    let n = NodeId(10);
    let json = serde_json::to_string(&n).unwrap();
    let deser: NodeId = serde_json::from_str(&json).unwrap();
    assert_eq!(n, deser);
}

#[test]
fn test_trace_hash_length() {
    let hash = compute_trace_hash(b"sample trace");
    assert_eq!(hash.len(), 32);
}
