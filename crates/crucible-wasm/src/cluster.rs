//! Multi-node WASM Cluster and Network Scheduling Harness.

use std::collections::{HashMap, HashSet, VecDeque};
use crate::runtime::{WasmInstance, WasmRuntimeConfig, StepOutcome};
use crate::snapshot::WasmSnapshot;
use sha2::{Digest, Sha256};

/// Message currently in-flight across the virtual network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InFlightMessage {
    pub src: u32,
    pub dst: u32,
    pub payload: Vec<u8>,
    pub deliver_at_ns: u64,
}

/// Snapshot of the entire cluster state (nodes + network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmClusterSnapshot {
    pub virtual_time_ns: u64,
    pub round_counter: u64,
    pub node_snapshots: HashMap<u32, WasmSnapshot>,
    pub in_flight: Vec<InFlightMessage>,
    pub network_partitions: HashSet<(u32, u32)>,
    pub cluster_hash: [u8; 32],
}

impl WasmClusterSnapshot {
    pub fn compute_cluster_hash(
        virtual_time_ns: u64,
        round_counter: u64,
        node_snapshots: &HashMap<u32, WasmSnapshot>,
        in_flight: &[InFlightMessage],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&virtual_time_ns.to_le_bytes());
        hasher.update(&round_counter.to_le_bytes());

        // Sort node snapshots by node_id for determinism
        let mut sorted_nodes: Vec<_> = node_snapshots.iter().collect();
        sorted_nodes.sort_by_key(|(&id, _)| id);

        for (&id, snap) in sorted_nodes {
            hasher.update(&id.to_le_bytes());
            hasher.update(&snap.state_hash);
        }

        hasher.update(&(in_flight.len() as u64).to_le_bytes());
        for msg in in_flight {
            hasher.update(&msg.src.to_le_bytes());
            hasher.update(&msg.dst.to_le_bytes());
            hasher.update(&msg.deliver_at_ns.to_le_bytes());
            hasher.update(&(msg.payload.len() as u64).to_le_bytes());
            hasher.update(&msg.payload);
        }

        hasher.finalize().into()
    }
}

/// Configuration for the multi-node WASM cluster.
#[derive(Debug, Clone)]
pub struct WasmClusterConfig {
    pub node_count: usize,
    pub fuel_slice_per_step: u64,
    pub message_delay_ns: u64,
    pub tick_interval_ns: u64,
}

impl Default for WasmClusterConfig {
    fn default() -> Self {
        Self {
            node_count: 3,
            fuel_slice_per_step: 100_000,
            message_delay_ns: 1_000_000, // 1 ms
            tick_interval_ns: 10_000_000, // 10 ms
        }
    }
}

/// Simulated Multi-Node WASM Cluster running consensus instances.
pub struct WasmCluster {
    pub config: WasmClusterConfig,
    pub nodes: HashMap<u32, WasmInstance>,
    pub virtual_time_ns: u64,
    pub round_counter: u64,
    pub in_flight: VecDeque<InFlightMessage>,
    pub network_partitions: HashSet<(u32, u32)>, // directed (src, dst) cuts
}

impl WasmCluster {
    /// Initialize a new WASM cluster from a compiled WASM module.
    pub fn new(
        wasm_bytes: &[u8],
        config: WasmClusterConfig,
        base_seed: u64,
    ) -> anyhow::Result<Self> {
        let mut nodes = HashMap::new();
        let runtime_cfg = WasmRuntimeConfig {
            default_fuel_slice: config.fuel_slice_per_step,
            ..Default::default()
        };

        for i in 0..config.node_count {
            let node_id = (i + 1) as u32;
            let node_seed = base_seed.wrapping_add((node_id as u64).wrapping_mul(0x9e3779b97f4a7c15));
            let mut instance = WasmInstance::new(wasm_bytes, node_id, node_seed, runtime_cfg.clone())?;

            // If module exports `init`, call it with (node_id, cluster_size)
            if let Some(init_fn) = instance.instance.get_func(&mut instance.store, "init") {
                let params = [
                    wasmtime::Val::I32(node_id as i32),
                    wasmtime::Val::I32(config.node_count as i32),
                ];
                instance.add_fuel(100_000)?;
                init_fn.call(&mut instance.store, &params, &mut [])?;
            }

            nodes.insert(node_id, instance);
        }

        Ok(Self {
            config,
            nodes,
            virtual_time_ns: 0,
            round_counter: 0,
            in_flight: VecDeque::new(),
            network_partitions: HashSet::new(),
        })
    }

    /// Add bidirectional network partition between two sets of nodes.
    pub fn partition(&mut self, partition_a: &[u32], partition_b: &[u32]) {
        for &a in partition_a {
            for &b in partition_b {
                self.network_partitions.insert((a, b));
                self.network_partitions.insert((b, a));
            }
        }
    }

    /// Heal all network partitions.
    pub fn heal_network(&mut self) {
        self.network_partitions.clear();
    }

    /// Step the cluster by one round:
    /// 1. Deliver ready network messages.
    /// 2. Step each node for `fuel_slice`.
    /// 3. Collect outbox messages and schedule delivery.
    /// 4. Advance virtual time.
    pub fn step_round(&mut self) -> anyhow::Result<u64> {
        self.round_counter += 1;
        self.virtual_time_ns += self.config.tick_interval_ns;
        let current_time = self.virtual_time_ns;

        // 1. Deliver in-flight messages due at or before current_time
        let mut undelivered = VecDeque::new();
        while let Some(msg) = self.in_flight.pop_front() {
            if msg.deliver_at_ns <= current_time {
                // Check network partition
                if !self.network_partitions.contains(&(msg.src, msg.dst)) {
                    if let Some(node) = self.nodes.get_mut(&msg.dst) {
                        node.enqueue_message(msg.payload);
                    }
                }
            } else {
                undelivered.push_back(msg);
            }
        }
        self.in_flight = undelivered;

        let mut total_fuel_this_round: u64 = 0;

        // 2. Step each node deterministically in ascending node_id order
        let mut node_ids: Vec<u32> = self.nodes.keys().copied().collect();
        node_ids.sort();

        let mut outgoing = Vec::new();

        for node_id in node_ids {
            let node = self.nodes.get_mut(&node_id).unwrap();
            node.set_virtual_time(current_time);

            let outcome = node.step_function("step", self.config.fuel_slice_per_step)?;
            match outcome {
                StepOutcome::Completed { fuel_consumed, .. } => {
                    total_fuel_this_round += fuel_consumed;
                }
                StepOutcome::OutOfFuel { fuel_consumed } => {
                    total_fuel_this_round += fuel_consumed;
                }
                StepOutcome::Exited { fuel_consumed, .. } => {
                    total_fuel_this_round += fuel_consumed;
                }
            }

            // Collect messages emitted by this node
            let msgs = node.drain_outbox();
            for (dst, payload) in msgs {
                outgoing.push(InFlightMessage {
                    src: node_id,
                    dst,
                    payload,
                    deliver_at_ns: current_time + self.config.message_delay_ns,
                });
            }
        }

        // 3. Queue outgoing messages
        for msg in outgoing {
            self.in_flight.push_back(msg);
        }

        Ok(total_fuel_this_round)
    }

    /// Capture snapshot of entire cluster state.
    pub fn snapshot(&self) -> anyhow::Result<WasmClusterSnapshot> {
        let mut node_snapshots = HashMap::new();
        for (&id, node) in &self.nodes {
            node_snapshots.insert(id, node.snapshot()?);
        }

        let in_flight_vec: Vec<InFlightMessage> = self.in_flight.iter().cloned().collect();
        let cluster_hash = WasmClusterSnapshot::compute_cluster_hash(
            self.virtual_time_ns,
            self.round_counter,
            &node_snapshots,
            &in_flight_vec,
        );

        Ok(WasmClusterSnapshot {
            virtual_time_ns: self.virtual_time_ns,
            round_counter: self.round_counter,
            node_snapshots,
            in_flight: in_flight_vec,
            network_partitions: self.network_partitions.clone(),
            cluster_hash,
        })
    }

    /// Restore entire cluster state from snapshot.
    pub fn restore(&mut self, snapshot: &WasmClusterSnapshot) -> anyhow::Result<()> {
        self.virtual_time_ns = snapshot.virtual_time_ns;
        self.round_counter = snapshot.round_counter;
        self.network_partitions = snapshot.network_partitions.clone();
        self.in_flight = snapshot.in_flight.iter().cloned().collect();

        for (&id, node_snap) in &snapshot.node_snapshots {
            if let Some(node) = self.nodes.get_mut(&id) {
                node.restore(node_snap)?;
            }
        }

        Ok(())
    }
}
