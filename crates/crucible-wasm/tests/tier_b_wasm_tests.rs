//! Comprehensive verification test suite for Crucible Tier B (WASM via Wasmtime).
//!
//! Verifies:
//! 1. Exact deterministic fuel consumption across repeated runs.
//! 2. Out-of-fuel preemption and graceful resumption.
//! 3. WASM linear memory state snapshot and bit-exact restoration.
//! 4. Page-level dirty diff tracking for CoW exploration trees.
//! 5. Multi-node Raft consensus cluster in WASM with leader election and log replication.
//! 6. Network partition resilience and recovery.
//! 7. 100% byte-exact replay across repeated independent runs (CLM-010).

use crucible_wasm::{
    WasmCluster, WasmClusterConfig, WasmInstance, WasmRuntimeConfig,
    runtime::StepOutcome,
};
use sha2::{Digest, Sha256};

const RAFT_WASM: &[u8] = include_bytes!("fixtures/raft_node.wasm");

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[test]
fn test_wasm_fuel_metering_determinism() {
    let seed = 0x4242_1337_cafe;
    let config = WasmRuntimeConfig {
        default_fuel_slice: 50_000,
        ..Default::default()
    };

    // Run 1
    let mut inst1 = WasmInstance::new(RAFT_WASM, 1, seed, config.clone()).unwrap();
    let mut fuel_consumed_1 = Vec::new();
    for _ in 0..10 {
        let outcome = inst1.step_function("step", 50_000).unwrap();
        match outcome {
            StepOutcome::Completed { fuel_consumed, .. } => fuel_consumed_1.push(fuel_consumed),
            StepOutcome::OutOfFuel { fuel_consumed } => fuel_consumed_1.push(fuel_consumed),
            StepOutcome::Exited { fuel_consumed, .. } => fuel_consumed_1.push(fuel_consumed),
        }
    }
    let hash1 = inst1.state_hash().unwrap();

    // Run 2 (identical seed)
    let mut inst2 = WasmInstance::new(RAFT_WASM, 1, seed, config).unwrap();
    let mut fuel_consumed_2 = Vec::new();
    for _ in 0..10 {
        let outcome = inst2.step_function("step", 50_000).unwrap();
        match outcome {
            StepOutcome::Completed { fuel_consumed, .. } => fuel_consumed_2.push(fuel_consumed),
            StepOutcome::OutOfFuel { fuel_consumed } => fuel_consumed_2.push(fuel_consumed),
            StepOutcome::Exited { fuel_consumed, .. } => fuel_consumed_2.push(fuel_consumed),
        }
    }
    let hash2 = inst2.state_hash().unwrap();

    assert_eq!(fuel_consumed_1, fuel_consumed_2, "Fuel consumption must be bit-identical across identical runs");
    assert_eq!(hash1, hash2, "Final state hash must match identically");
    println!("Fuel consumed across 10 steps: {:?}", fuel_consumed_1);
}

#[test]
fn test_wasm_out_of_fuel_preemption() {
    let mut inst = WasmInstance::new(RAFT_WASM, 1, 999, WasmRuntimeConfig::default()).unwrap();

    // Provide 0 fuel units which must immediately exhaust
    let outcome = inst.step_function("step", 0).unwrap();
    match outcome {
        StepOutcome::OutOfFuel { fuel_consumed } => {
            assert_eq!(fuel_consumed, 0);
            println!("Preemption verified: OutOfFuel trapped cleanly at {} fuel", fuel_consumed);
        }
        _ => panic!("Expected OutOfFuel with 0 fuel units, got {:?}", outcome),
    }

    // Now replenish fuel and resume
    let outcome2 = inst.step_function("step", 100_000).unwrap();
    match outcome2 {
        StepOutcome::Completed { fuel_consumed, .. } => {
            assert!(fuel_consumed > 0);
            println!("Resumed cleanly with replenished fuel, consumed {} fuel", fuel_consumed);
        }
        _ => panic!("Expected Completed after fuel replenish, got {:?}", outcome2),
    }
}

#[test]
fn test_wasm_memory_snapshot_and_bit_exact_restore() {
    let seed = 0xbeef_1234;
    let config = WasmRuntimeConfig {
        default_fuel_slice: 100_000,
        ..Default::default()
    };
    let mut inst = WasmInstance::new(RAFT_WASM, 1, seed, config).unwrap();

    // Run for 15 steps
    for step in 1..=15 {
        inst.set_virtual_time((step * 10) * 1_000_000);
        inst.step_function("step", 100_000).unwrap();
    }

    // Take checkpoint snapshot at step 15
    let snapshot_15 = inst.snapshot().unwrap();
    let hash_at_15 = snapshot_15.state_hash;

    // Run 20 more steps to step 35 (modifying state)
    for step in 16..=35 {
        inst.set_virtual_time((step * 10) * 1_000_000);
        inst.step_function("step", 100_000).unwrap();
    }
    let hash_at_35 = inst.state_hash().unwrap();
    assert_ne!(hash_at_15, hash_at_35, "State must have changed between step 15 and 35");

    // Check dirty pages between step 15 and step 35
    let snap_35 = inst.snapshot().unwrap();
    let dirty = snap_35.dirty_pages_since(&snapshot_15);
    println!("Dirty pages modified between step 15 and 35: {:?}", dirty);
    assert!(!dirty.is_empty(), "At least one memory page must be modified");

    // Restore back to step 15 snapshot
    inst.restore(&snapshot_15).unwrap();
    let restored_hash = inst.state_hash().unwrap();
    assert_eq!(hash_at_15, restored_hash, "Restored state hash must be bit-exact identical to step 15 snapshot");

    // Run forward again from restored step 15 to step 35
    for step in 16..=35 {
        inst.set_virtual_time((step * 10) * 1_000_000);
        inst.step_function("step", 100_000).unwrap();
    }
    let replay_hash_35 = inst.state_hash().unwrap();
    assert_eq!(hash_at_35, replay_hash_35, "Replayed state from restored snapshot must be bit-exact identical");
}

#[test]
fn test_wasm_multi_node_raft_cluster() {
    let cluster_config = WasmClusterConfig {
        node_count: 3,
        fuel_slice_per_step: 150_000,
        message_delay_ns: 2_000_000,  // 2ms
        tick_interval_ns: 10_000_000, // 10ms
    };

    let mut cluster = WasmCluster::new(RAFT_WASM, cluster_config, 0xcafe_9999).unwrap();

    // Run cluster for up to 35 rounds (350ms virtual time) to allow leader election
    let mut elected_leader = None;
    let node_ids = vec![1u32, 2u32, 3u32];

    for round in 1..=35 {
        cluster.step_round().unwrap();

        // Check node roles
        for &id in &node_ids {
            let node = cluster.nodes.get_mut(&id).unwrap();
            let role_func = node.instance.get_func(&mut node.store, "get_role").unwrap();
            let mut results = [wasmtime::Val::I32(0)];
            role_func.call(&mut node.store, &[], &mut results).unwrap();
            let role = results[0].i32().unwrap();
            if role == 2 { // Leader
                elected_leader = Some(id);
                println!("Leader elected at round {}: Node {}", round, id);
                break;
            }
        }
        if elected_leader.is_some() {
            break;
        }
    }

    assert!(elected_leader.is_some(), "A leader must be elected within 350ms of virtual time");
    let leader_id = elected_leader.unwrap();

    // Propose client writes to leader
    {
        let leader_node = cluster.nodes.get_mut(&leader_id).unwrap();
        let propose_func = leader_node.instance.get_func(&mut leader_node.store, "propose").unwrap();
        let mut results = [wasmtime::Val::I32(0)];
        // Propose key=1, val=100
        propose_func.call(&mut leader_node.store, &[wasmtime::Val::I32(1), wasmtime::Val::I32(100)], &mut results).unwrap();
        assert_eq!(results[0].i32().unwrap(), 1, "Log index 1 proposed");

        // Propose key=2, val=200
        propose_func.call(&mut leader_node.store, &[wasmtime::Val::I32(2), wasmtime::Val::I32(200)], &mut results).unwrap();
        assert_eq!(results[0].i32().unwrap(), 2, "Log index 2 proposed");
    }

    // Step cluster for 25 more rounds to allow AppendEntries replication and majority commit
    for _ in 0..25 {
        cluster.step_round().unwrap();
    }

    // Verify commit index and KV store on leader and followers
    for &id in &node_ids {
        let node = cluster.nodes.get_mut(&id).unwrap();
        let commit_func = node.instance.get_func(&mut node.store, "get_commit_index").unwrap();
        let mut results = [wasmtime::Val::I32(0)];
        commit_func.call(&mut node.store, &[], &mut results).unwrap();
        let commit_idx = results[0].i32().unwrap();
        println!("Node {} commit index: {}", id, commit_idx);
        assert!(commit_idx >= 2, "Entries must be committed across the cluster");

        // Read key 1 and key 2 from KV store
        let read_func = node.instance.get_func(&mut node.store, "read").unwrap();
        read_func.call(&mut node.store, &[wasmtime::Val::I32(1)], &mut results).unwrap();
        assert_eq!(results[0].i32().unwrap(), 100, "Node {} key 1 must be 100", id);

        read_func.call(&mut node.store, &[wasmtime::Val::I32(2)], &mut results).unwrap();
        assert_eq!(results[0].i32().unwrap(), 200, "Node {} key 2 must be 200", id);
    }
}

#[test]
fn test_wasm_raft_partition_and_cluster_snapshot() {
    let cluster_config = WasmClusterConfig {
        node_count: 3,
        fuel_slice_per_step: 150_000,
        message_delay_ns: 2_000_000,
        tick_interval_ns: 10_000_000,
    };

    let mut cluster = WasmCluster::new(RAFT_WASM, cluster_config, 0x1234_5678).unwrap();

    // Step to election
    for _ in 0..30 {
        cluster.step_round().unwrap();
    }

    // Capture whole-cluster snapshot
    let snapshot_pre_partition = cluster.snapshot().unwrap();

    // Partition Node 3 from Nodes 1 & 2
    cluster.partition(&[3], &[1, 2]);

    // Run 20 rounds under partition
    for _ in 0..20 {
        cluster.step_round().unwrap();
    }

    // Heal partition
    cluster.heal_network();

    // Run 20 rounds post-heal
    for _ in 0..20 {
        cluster.step_round().unwrap();
    }
    let post_heal_hash = cluster.snapshot().unwrap().cluster_hash;

    // Restore cluster to pre-partition snapshot
    cluster.restore(&snapshot_pre_partition).unwrap();
    let restored_cluster_hash = cluster.snapshot().unwrap().cluster_hash;
    assert_eq!(snapshot_pre_partition.cluster_hash, restored_cluster_hash, "Cluster hash must restore bit-identically");

    // Replay partition and healing from restored snapshot
    cluster.partition(&[3], &[1, 2]);
    for _ in 0..20 {
        cluster.step_round().unwrap();
    }
    cluster.heal_network();
    for _ in 0..20 {
        cluster.step_round().unwrap();
    }

    let replayed_cluster_hash = cluster.snapshot().unwrap().cluster_hash;
    assert_eq!(post_heal_hash, replayed_cluster_hash, "Cluster state must replay bit-identically after restore");
}

#[test]
fn test_clm_010_wasm_byte_exact_replay() {
    let cluster_config = WasmClusterConfig {
        node_count: 3,
        fuel_slice_per_step: 120_000,
        message_delay_ns: 2_000_000,
        tick_interval_ns: 10_000_000,
    };

    let seeds = [
        0xDEAD_BEEF_0001,
        0xDEAD_BEEF_0002,
        0xDEAD_BEEF_0003,
    ];

    let node_ids = vec![1u32, 2u32, 3u32];

    for &seed in &seeds {
        // Run 1
        let mut cluster1 = WasmCluster::new(RAFT_WASM, cluster_config.clone(), seed).unwrap();
        let mut trace_hasher1 = Sha256::new();

        for round in 1u64..=60 {
            let fuel = cluster1.step_round().unwrap();
            trace_hasher1.update(&round.to_le_bytes());
            trace_hasher1.update(&fuel.to_le_bytes());

            // Propose at round 25
            if round == 25 {
                let mut leader_id = 1u32;
                for &id in &node_ids {
                    let node = cluster1.nodes.get_mut(&id).unwrap();
                    let func = node.instance.get_func(&mut node.store, "get_role").unwrap();
                    let mut res = [wasmtime::Val::I32(0)];
                    func.call(&mut node.store, &[], &mut res).unwrap();
                    if res[0].i32().unwrap() == 2 {
                        leader_id = id;
                        break;
                    }
                }

                let node = cluster1.nodes.get_mut(&leader_id).unwrap();
                let prop = node.instance.get_func(&mut node.store, "propose").unwrap();
                let _ = prop.call(&mut node.store, &[wasmtime::Val::I32(3), wasmtime::Val::I32(333)], &mut [wasmtime::Val::I32(0)]);
            }

            // Partition at round 40
            if round == 40 {
                cluster1.partition(&[2], &[1, 3]);
            }
            // Heal at round 50
            if round == 50 {
                cluster1.heal_network();
            }
        }
        let cluster1_snap = cluster1.snapshot().unwrap();
        trace_hasher1.update(&cluster1_snap.cluster_hash);
        let final_trace_hash_1: [u8; 32] = trace_hasher1.finalize().into();

        // Run 2 (Independent fresh run with identical seed)
        let mut cluster2 = WasmCluster::new(RAFT_WASM, cluster_config.clone(), seed).unwrap();
        let mut trace_hasher2 = Sha256::new();

        for round in 1u64..=60 {
            let fuel = cluster2.step_round().unwrap();
            trace_hasher2.update(&round.to_le_bytes());
            trace_hasher2.update(&fuel.to_le_bytes());

            if round == 25 {
                let mut leader_id = 1u32;
                for &id in &node_ids {
                    let node = cluster2.nodes.get_mut(&id).unwrap();
                    let func = node.instance.get_func(&mut node.store, "get_role").unwrap();
                    let mut res = [wasmtime::Val::I32(0)];
                    func.call(&mut node.store, &[], &mut res).unwrap();
                    if res[0].i32().unwrap() == 2 {
                        leader_id = id;
                        break;
                    }
                }

                let node = cluster2.nodes.get_mut(&leader_id).unwrap();
                let prop = node.instance.get_func(&mut node.store, "propose").unwrap();
                let _ = prop.call(&mut node.store, &[wasmtime::Val::I32(3), wasmtime::Val::I32(333)], &mut [wasmtime::Val::I32(0)]);
            }

            if round == 40 {
                cluster2.partition(&[2], &[1, 3]);
            }
            if round == 50 {
                cluster2.heal_network();
            }
        }
        let cluster2_snap = cluster2.snapshot().unwrap();
        trace_hasher2.update(&cluster2_snap.cluster_hash);
        let final_trace_hash_2: [u8; 32] = trace_hasher2.finalize().into();

        assert_eq!(
            final_trace_hash_1, final_trace_hash_2,
            "CLM-010 VIOLATION: Execution trace hash diverged between run 1 and run 2 for seed 0x{:X}",
            seed
        );
        assert_eq!(
            cluster1_snap.cluster_hash, cluster2_snap.cluster_hash,
            "CLM-010 VIOLATION: Final cluster state hash diverged between run 1 and run 2 for seed 0x{:X}",
            seed
        );

        println!(
            "Seed 0x{:X}: CLM-010 Verified! Trace Hash: {}",
            seed,
            to_hex(&final_trace_hash_1)
        );
    }
}
