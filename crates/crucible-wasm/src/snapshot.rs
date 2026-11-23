//! WASM linear memory and execution state snapshots.
//!
//! Provides byte-exact checkpointing and restoration of:
//! - Linear memory bytes
//! - Fuel state
//! - Virtual clock timestamp
//! - In-flight inbox / outbox network queues
//! - PRNG state and step counters
//! - Page-level dirty diffs for CoW exploration trees

use std::collections::VecDeque;
use rand_chacha::ChaCha8Rng;
use sha2::{Digest, Sha256};
use crate::runtime::WasmInstance;

/// WASM page size is 64 KiB (65,536 bytes).
pub const WASM_PAGE_SIZE: usize = 65536;

/// Complete deterministic snapshot of a WASM instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WasmSnapshot {
    pub node_id: u32,
    pub memory_bytes: Vec<u8>,
    pub fuel_remaining: u64,
    pub virtual_time_ns: u64,
    pub step_counter: u64,
    pub total_fuel_consumed: u64,
    pub prng: ChaCha8Rng,
    pub inbox: VecDeque<Vec<u8>>,
    pub outbox: VecDeque<(u32, Vec<u8>)>,
    pub stdout_buf: Vec<u8>,
    pub stderr_buf: Vec<u8>,
    pub exit_code: Option<i32>,
    pub state_hash: [u8; 32],
}

impl WasmSnapshot {
    /// Compute cryptographic SHA-256 fingerprint of the snapshot.
    pub fn compute_hash(
        node_id: u32,
        virtual_time_ns: u64,
        step_counter: u64,
        fuel_remaining: u64,
        total_fuel_consumed: u64,
        memory_bytes: &[u8],
        inbox: &VecDeque<Vec<u8>>,
        outbox: &VecDeque<(u32, Vec<u8>)>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&node_id.to_le_bytes());
        hasher.update(&virtual_time_ns.to_le_bytes());
        hasher.update(&step_counter.to_le_bytes());
        hasher.update(&fuel_remaining.to_le_bytes());
        hasher.update(&total_fuel_consumed.to_le_bytes());
        hasher.update(&(memory_bytes.len() as u64).to_le_bytes());
        hasher.update(memory_bytes);

        // Hash in-flight network messages
        hasher.update(&(inbox.len() as u64).to_le_bytes());
        for msg in inbox {
            hasher.update(&(msg.len() as u64).to_le_bytes());
            hasher.update(msg);
        }

        hasher.update(&(outbox.len() as u64).to_le_bytes());
        for (dst, msg) in outbox {
            hasher.update(&dst.to_le_bytes());
            hasher.update(&(msg.len() as u64).to_le_bytes());
            hasher.update(msg);
        }

        hasher.finalize().into()
    }

    /// Size of linear memory in WASM pages (64 KB each).
    pub fn memory_pages(&self) -> usize {
        self.memory_bytes.len() / WASM_PAGE_SIZE
    }

    /// Compute modified page indices compared to a base snapshot.
    pub fn dirty_pages_since(&self, base: &WasmSnapshot) -> Vec<usize> {
        let max_pages = self.memory_pages().max(base.memory_pages());
        let mut dirty = Vec::new();

        for page_idx in 0..max_pages {
            let start = page_idx * WASM_PAGE_SIZE;
            let end = start + WASM_PAGE_SIZE;

            let self_page = if start < self.memory_bytes.len() {
                let p_end = end.min(self.memory_bytes.len());
                &self.memory_bytes[start..p_end]
            } else {
                &[]
            };

            let base_page = if start < base.memory_bytes.len() {
                let p_end = end.min(base.memory_bytes.len());
                &base.memory_bytes[start..p_end]
            } else {
                &[]
            };

            if self_page != base_page {
                dirty.push(page_idx);
            }
        }

        dirty
    }
}

impl WasmInstance {
    /// Capture a complete, byte-exact snapshot of the current instance state.
    pub fn snapshot(&self) -> anyhow::Result<WasmSnapshot> {
        let mem = self.memory.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Memory export not found"))?;
        let memory_bytes = mem.data(&self.store).to_vec();
        let fuel_remaining = self.get_fuel();
        let host_data = self.store.data();

        let state_hash = WasmSnapshot::compute_hash(
            host_data.node_id,
            host_data.virtual_time_ns,
            host_data.step_counter,
            fuel_remaining,
            host_data.total_fuel_consumed,
            &memory_bytes,
            &host_data.inbox,
            &host_data.outbox,
        );

        Ok(WasmSnapshot {
            node_id: host_data.node_id,
            memory_bytes,
            fuel_remaining,
            virtual_time_ns: host_data.virtual_time_ns,
            step_counter: host_data.step_counter,
            total_fuel_consumed: host_data.total_fuel_consumed,
            prng: host_data.prng.clone(),
            inbox: host_data.inbox.clone(),
            outbox: host_data.outbox.clone(),
            stdout_buf: host_data.stdout_buf.clone(),
            stderr_buf: host_data.stderr_buf.clone(),
            exit_code: host_data.exit_code,
            state_hash,
        })
    }

    /// Restore the instance to an exact prior snapshot.
    pub fn restore(&mut self, snapshot: &WasmSnapshot) -> anyhow::Result<()> {
        let mem = self.memory.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Memory export not found"))?;

        // Ensure memory is large enough
        let current_len = mem.data(&self.store).len();
        if snapshot.memory_bytes.len() > current_len {
            let pages_needed = (snapshot.memory_bytes.len() - current_len + WASM_PAGE_SIZE - 1) / WASM_PAGE_SIZE;
            mem.grow(&mut self.store, pages_needed as u64)?;
        }

        // Restore linear memory content
        let (data, _) = mem.data_and_store_mut(&mut self.store);
        data[..snapshot.memory_bytes.len()].copy_from_slice(&snapshot.memory_bytes);

        // Restore fuel
        self.set_fuel(snapshot.fuel_remaining)?;

        // Restore host context
        let host_data = self.store.data_mut();
        host_data.virtual_time_ns = snapshot.virtual_time_ns;
        host_data.step_counter = snapshot.step_counter;
        host_data.total_fuel_consumed = snapshot.total_fuel_consumed;
        host_data.prng = snapshot.prng.clone();
        host_data.inbox = snapshot.inbox.clone();
        host_data.outbox = snapshot.outbox.clone();
        host_data.stdout_buf = snapshot.stdout_buf.clone();
        host_data.stderr_buf = snapshot.stderr_buf.clone();
        host_data.exit_code = snapshot.exit_code;

        Ok(())
    }
}
