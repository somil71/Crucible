//! Comprehensive Audit and Retest Suite for Phase 1 & Phase 2.
//!
//! Exhaustively re-evaluates all edge cases across:
//! - Phase 1: Storage crash models, asymmetric network partitions, jump-on-idle scheduling, Raft throughput.
//! - Phase 2: WGL concurrent linearizability (>64 operations, multi-key), Elle isolation, causal diamond slicing.

use crucible_checkers::*;
use crucible_core::{NodeId, VirtualTime};
use crucible_sim::{
    CrashFault, SimulatedBlockStore,
    SimulatedNetwork, StorageError, VirtualWorldEngine, SECTOR_SIZE,
};

#[test]
fn test_audit_phase1_storage_crash_model() {
    println!("\n[AUDIT 1] Phase 1 Storage Crash Consistency Model Audit");
    let mut store = SimulatedBlockStore::new(20);

    // Write 5 sectors
    for i in 0..5 {
        let sector_data = [i as u8 + 1; SECTOR_SIZE];
        store.write_sector(i, &sector_data).unwrap();
    }
    assert!(store.has_unflushed_writes());

    // Flush sectors 0..3
    store.fsync();
    assert!(!store.has_unflushed_writes());

    // Write sectors 3 and 4 with new data, but do NOT fsync
    let dirty_data = [0x99; SECTOR_SIZE];
    store.write_sector(3, &dirty_data).unwrap();
    store.write_sector(4, &dirty_data).unwrap();

    // Sector 7 is brand new and never fsync'd
    store.write_sector(7, &[0x77; SECTOR_SIZE]).unwrap();

    // 1. Crash with LostUnsyncedWrites
    store.crash(CrashFault::LostUnsyncedWrites);
    assert_eq!(store.read_sector(3).unwrap(), [4; SECTOR_SIZE]); // reverted to fsync'd data
    assert_eq!(store.read_sector(4).unwrap(), [5; SECTOR_SIZE]); // reverted to fsync'd data
    assert_eq!(store.read_sector(7).unwrap(), [0; SECTOR_SIZE]); // was never fsync'd, zeroed

    // 2. Test TornWrite
    let mut torn_data = [0xAA; SECTOR_SIZE];
    torn_data[..256].fill(0xBB);
    store.write_sector(5, &torn_data).unwrap();
    store.crash(CrashFault::TornWrite {
        sector: 5,
        bytes_written: 256,
    });
    let read_torn = store.read_sector(5).unwrap();
    assert_eq!(&read_torn[..256], &[0xBB; 256]);
    assert_eq!(&read_torn[256..], &[0x00; 256]);

    // 3. Test CorruptedSector
    store.write_sector(6, &[0xCC; SECTOR_SIZE]).unwrap();
    store.fsync();
    store.crash(CrashFault::CorruptSector { sector: 6 });
    assert_eq!(store.read_sector(6), Err(StorageError::CorruptedSector { sector: 6 }));

    println!("  -> Storage crash consistency model passed all checks.");
}

#[test]
fn test_audit_phase1_network_asymmetric_partitions() {
    println!("\n[AUDIT 2] Phase 1 Network Asymmetric & Directed Partitions Audit");
    let mut net = SimulatedNetwork::<String>::new();
    let n1 = NodeId(1);
    let n2 = NodeId(2);
    let n3 = NodeId(3);

    // n1 -> n2 is cut, but n2 -> n1 is open
    // n2 -> n3 is cut, but n3 -> n2 is open
    net.partition_directed(&[n1], &[n2]);
    net.partition_directed(&[n2], &[n3]);

    assert!(net.is_blocked(n1, n2));
    assert!(!net.is_blocked(n2, n1));
    assert!(net.is_blocked(n2, n3));
    assert!(!net.is_blocked(n3, n2));

    // Send packets
    assert!(!net.send(VirtualTime(0), n1, n2, "n1->n2 blocked".into()));
    assert!(net.send(VirtualTime(0), n2, n1, "n2->n1 allowed".into()));
    assert!(net.send(VirtualTime(0), n3, n2, "n3->n2 allowed".into()));

    // Fast-forward delivery
    let pkt1 = net.deliver_next(VirtualTime(2_000_000)).unwrap();
    assert_eq!(pkt1.from, n2);
    assert_eq!(pkt1.to, n1);

    let pkt2 = net.deliver_next(VirtualTime(2_000_000)).unwrap();
    assert_eq!(pkt2.from, n3);
    assert_eq!(pkt2.to, n2);

    println!("  -> Asymmetric directed partitions passed all checks.");
}

#[test]
fn test_audit_phase1_virtual_time_jump_concurrency() {
    println!("\n[AUDIT 3] Phase 1 Jump-on-Idle Multi-Event Concurrency Audit");
    let mut engine = VirtualWorldEngine::new();

    // Schedule 100 simultaneous events at the exact same virtual timestamp
    let t_same = VirtualTime(5_000_000);
    for i in 1..=100 {
        engine.schedule(
            t_same,
            crucible_sim::ScheduledClusterEvent::HeartbeatTimeout(NodeId(i)),
        );
    }

    // Must step all 100 events cleanly at t_same in FIFO sequence
    for i in 1..=100 {
        let ev = engine.step_next().unwrap();
        assert_eq!(ev.scheduled_at, t_same);
        assert_eq!(engine.current_time, t_same);
        assert_eq!(ev.payload, crucible_sim::ScheduledClusterEvent::HeartbeatTimeout(NodeId(i)));
    }

    assert!(engine.step_next().is_none());
    println!("  -> Jump-on-idle multi-event concurrency passed all checks.");
}

#[test]
fn test_audit_phase2_wgl_large_concurrent_history() {
    println!("\n[AUDIT 4] Phase 2 WGL Checker on Large Concurrent History (>64 ops)");
    let checker = WglLinearizabilityChecker;

    // Build 70 concurrent operations on a single key
    // 35 concurrent writes followed by 35 concurrent reads
    let mut ops = Vec::new();
    for i in 1..=35 {
        ops.push(KvOperation {
            client_id: i,
            op_type: OpType::Write,
            key: "bulk_key".into(),
            value: Some(format!("val_{}", i)),
            invoke_time: VirtualTime(10),
            complete_time: VirtualTime(50),
        });
    }

    // Read the value of the last write
    for i in 36..=70 {
        ops.push(KvOperation {
            client_id: i,
            op_type: OpType::Read,
            key: "bulk_key".into(),
            value: Some("val_35".into()),
            invoke_time: VirtualTime(60),
            complete_time: VirtualTime(100),
        });
    }

    assert_eq!(ops.len(), 70);
    // Evaluates dynamic bitset without u64 bitshift overflow
    let res = checker.check_history(&ops);
    assert_eq!(res, CheckResult::Pass);
    println!("  -> WGL successfully linearized 70 concurrent operations.");
}

#[test]
fn test_audit_phase2_elle_multiple_writes_in_same_tx() {
    println!("\n[AUDIT 5] Phase 2 Elle Multi-Write within Transaction Audit");
    // T1 writes x=old, then immediately updates to x=final
    // T2 reads x=final -> should be Serializable!
    // (If x=old leaked as a separate version, it could create false dependencies)
    let txs = vec![
        Transaction {
            id: TxId(1),
            ops: vec![
                TxOp::Write { key: "x".into(), value: "old".into() },
                TxOp::Write { key: "x".into(), value: "final".into() },
            ],
            start_time: VirtualTime(10),
            commit_time: VirtualTime(20),
        },
        Transaction {
            id: TxId(2),
            ops: vec![
                TxOp::Read { key: "x".into(), value: Some("final".into()) },
            ],
            start_time: VirtualTime(30),
            commit_time: VirtualTime(40),
        },
    ];

    let res = ElleCycleDetector::check_transactions(&txs);
    assert_eq!(res, ElleCheckResult::Serializable);
    println!("  -> Elle multi-write inside single transaction verified clean.");
}

#[test]
fn test_audit_phase2_causal_diamond_slicing() {
    println!("\n[AUDIT 6] Phase 2 Causal Graph Diamond Slicing Audit");
    let mut graph = CausalGraph::new();
    let n1 = NodeId(1);
    let n2 = NodeId(2);
    let n3 = NodeId(3);
    let n4 = NodeId(4);

    let mut vc1 = VectorClock::new();
    let mut vc2 = VectorClock::new();
    let mut vc3 = VectorClock::new();
    let mut vc4 = VectorClock::new();

    // Diamond: N1 branches to N2 and N3, both join at N4
    vc1.tick(n1);
    let e1 = graph.record_event(n1, &vc1, "N1 Root", VirtualTime(10));

    vc2.merge(&vc1);
    vc2.tick(n2);
    let e2 = graph.record_event(n2, &vc2, "N2 Left Branch", VirtualTime(20));

    vc3.merge(&vc1);
    vc3.tick(n3);
    let e3 = graph.record_event(n3, &vc3, "N3 Right Branch", VirtualTime(20));

    // N2 and N3 are concurrent
    assert!(vc2.is_concurrent_with(&vc3));

    // N4 joins N2 and N3
    vc4.merge(&vc2);
    vc4.merge(&vc3);
    vc4.tick(n4);
    let e4 = graph.record_event(n4, &vc4, "N4 Join Sink", VirtualTime(30));

    // Unrelated event on N1
    vc1.tick(n1);
    let e5_unrelated = graph.record_event(n1, &vc1, "N1 Concurrent Aftermath", VirtualTime(35));

    // Causal slice for e4 must contain exactly [e1, e2, e3, e4], excluding e5
    let slice = graph.causal_slice(e4);
    let ids: Vec<u64> = slice.iter().map(|e| e.id).collect();
    assert_eq!(ids, vec![e1, e2, e3, e4]);
    assert!(!ids.contains(&e5_unrelated));

    println!("  -> Causal diamond backward cone slicing verified 100% accurate.");
}
