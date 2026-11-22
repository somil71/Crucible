//! Deterministic Fuel-Metered WASM Instance Runtime.

use anyhow::Context;
use wasmtime::*;
use crate::wasi::{register_wasi_and_host_imports, WasmHostContext};

#[derive(Debug, Clone)]
pub struct WasmRuntimeConfig {
    pub default_fuel_slice: u64,
    pub max_memory_pages: u32,
    pub deterministic_nan: bool,
}

impl Default for WasmRuntimeConfig {
    fn default() -> Self {
        Self {
            default_fuel_slice: 100_000,
            max_memory_pages: 256, // 16 MB max linear memory
            deterministic_nan: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    Completed { fuel_consumed: u64, return_value: i32 },
    OutOfFuel { fuel_consumed: u64 },
    Exited { exit_code: i32, fuel_consumed: u64 },
}

pub struct WasmInstance {
    pub engine: Engine,
    pub module: Module,
    pub store: Store<WasmHostContext>,
    pub instance: Instance,
    pub memory: Option<Memory>,
    pub config: WasmRuntimeConfig,
}

impl WasmInstance {
    /// Create and initialize a new WASM instance from byte-bytecode or WAT.
    pub fn new(wasm_bytes: &[u8], node_id: u32, seed: u64, config: WasmRuntimeConfig) -> anyhow::Result<Self> {
        let mut wasm_config = Config::new();
        wasm_config.consume_fuel(true);
        if config.deterministic_nan {
            wasm_config.cranelift_nan_canonicalization(true);
        }
        // Strict single-threaded deterministic compilation
        wasm_config.parallel_compilation(false);

        let engine = Engine::new(&wasm_config)?;
        let module = Module::new(&engine, wasm_bytes).context("failed to compile wasm module")?;

        let host_ctx = WasmHostContext::new(node_id, seed);
        let mut store = Store::new(&engine, host_ctx);

        let mut linker = Linker::new(&engine);
        register_wasi_and_host_imports(&mut linker)?;

        let instance = linker.instantiate(&mut store, &module).context("failed to instantiate wasm module")?;
        let memory = instance.get_memory(&mut store, "memory");

        Ok(Self {
            engine,
            module,
            store,
            instance,
            memory,
            config,
        })
    }

    /// Set virtual clock timestamp for this node.
    pub fn set_virtual_time(&mut self, time_ns: u64) {
        self.store.data_mut().virtual_time_ns = time_ns;
    }

    /// Current virtual clock timestamp.
    pub fn virtual_time(&self) -> u64 {
        self.store.data().virtual_time_ns
    }

    /// Enqueue an incoming message into the node's inbox.
    pub fn enqueue_message(&mut self, msg: Vec<u8>) {
        self.store.data_mut().inbox.push_back(msg);
    }

    /// Drain all messages emitted by the node during its execution.
    pub fn drain_outbox(&mut self) -> Vec<(u32, Vec<u8>)> {
        self.store.data_mut().outbox.drain(..).collect()
    }

    /// Get current fuel level in store.
    pub fn get_fuel(&self) -> u64 {
        self.store.get_fuel().unwrap_or(0)
    }

    /// Add fuel to the store.
    pub fn add_fuel(&mut self, fuel: u64) -> anyhow::Result<()> {
        let current = self.store.get_fuel().unwrap_or(0);
        self.store.set_fuel(current + fuel)?;
        Ok(())
    }

    /// Set exact fuel in store.
    pub fn set_fuel(&mut self, fuel: u64) -> anyhow::Result<()> {
        self.store.set_fuel(fuel)?;
        Ok(())
    }

    /// Total fuel consumed across entire execution history.
    pub fn total_fuel_consumed(&self) -> u64 {
        self.store.data().total_fuel_consumed
    }

    /// Execute a step function (e.g. `crucible_step` or `step`) with exact fuel slice.
    pub fn step_function(&mut self, func_name: &str, fuel_slice: u64) -> anyhow::Result<StepOutcome> {
        self.add_fuel(fuel_slice)?;
        let initial_fuel = self.store.get_fuel()?;

        let func = self.instance.get_func(&mut self.store, func_name)
            .ok_or_else(|| anyhow::anyhow!("Exported function '{}' not found", func_name))?;

        let mut results = [Val::I32(0)];
        let call_res = func.call(&mut self.store, &[], &mut results);

        let remaining_fuel = self.store.get_fuel().unwrap_or(0);
        let fuel_consumed = initial_fuel.saturating_sub(remaining_fuel);
        self.store.data_mut().total_fuel_consumed += fuel_consumed;
        self.store.data_mut().step_counter += 1;

        if let Some(code) = self.store.data().exit_code {
            return Ok(StepOutcome::Exited {
                exit_code: code,
                fuel_consumed,
            });
        }

        match call_res {
            Ok(_) => {
                let rval = results[0].i32().unwrap_or(0);
                Ok(StepOutcome::Completed {
                    fuel_consumed,
                    return_value: rval,
                })
            }
            Err(trap) => {
                // Check if trap is due to fuel exhaustion anywhere in error cause chain
                let full_err = format!("{:#}", trap);
                if full_err.contains("all fuel consumed") || full_err.contains("out of fuel") {
                    Ok(StepOutcome::OutOfFuel { fuel_consumed })
                } else {
                    Err(trap)
                }
            }
        }
    }

    /// Get current linear memory bytes.
    pub fn memory_data(&self) -> anyhow::Result<&[u8]> {
        let mem = self.memory.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Memory export not found"))?;
        Ok(mem.data(&self.store))
    }

    /// Compute cryptographic SHA-256 fingerprint of current WASM memory and state.
    pub fn state_hash(&self) -> anyhow::Result<[u8; 32]> {
        Ok(self.snapshot()?.state_hash)
    }
}
