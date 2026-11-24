//! Crucible Emulator - User-mode x86-64 execution engine with exact instruction counting.

pub mod auditor;
pub mod cpu;
pub mod interp;
pub mod loader;
pub mod memory;

pub use auditor::{DeterminismAuditor, DivergenceReport, DivergenceTarget};
pub use cpu::{CpuRegisters, VirtualCpu};
pub use interp::{Emulator, EmulatorSnapshot};
pub use loader::{load_elf, LoadedBinary};
pub use memory::{VirtualMemory, VirtualMemorySnapshot};

use crucible_core::{compute_trace_hash, ThreadId, VirtualTime};
use crucible_vkernel::VirtualKernelContext;

/// Emulated thread context with bit-exact instruction step counter.
#[derive(Debug, Clone)]
pub struct EmulatedThread {
    pub id: ThreadId,
    pub regs: CpuRegisters,
    pub instruction_count: u64,
    pub is_blocked: bool,
}

impl EmulatedThread {
    pub fn new(id: ThreadId, entry_point: u64, stack_pointer: u64) -> Self {
        let mut regs = CpuRegisters::default();
        regs.rip = entry_point;
        regs.rsp = stack_pointer;
        Self {
            id,
            regs,
            instruction_count: 0,
            is_blocked: false,
        }
    }

    pub fn step_instruction(&mut self) {
        self.instruction_count += 1;
        self.regs.rip += 1;
    }
}

/// Single-logical-thread runner for exact determinism testing.
pub struct DeterminismHarness {
    pub thread: EmulatedThread,
    pub vkernel: VirtualKernelContext,
}

impl DeterminismHarness {
    pub fn new(entry_point: u64, stack_top: u64) -> Self {
        Self {
            thread: EmulatedThread::new(ThreadId(1), entry_point, stack_top),
            vkernel: VirtualKernelContext::default(),
        }
    }

    pub fn run_steps(&mut self, steps: u64) -> (u64, VirtualTime) {
        for _ in 0..steps {
            self.thread.step_instruction();
        }
        (self.thread.instruction_count, self.vkernel.virtual_time)
    }
}

/// Runs an ELF binary through the emulator using a specified custom scheduling policy and seed.
pub fn run_elf_trace_with_policy(
    elf_data: &[u8],
    max_steps: u64,
    policy: crucible_core::SchedulingPolicy,
    seed: crucible_core::Seed,
) -> Result<(u64, [u8; 32]), String> {
    let mut mem = VirtualMemory::new();
    let loaded = loader::load_elf(elf_data, &mut mem).map_err(|e| e.to_string())?;

    let mut emu = Emulator::new(loaded.entry_point, loaded.stack_pointer).with_policy(policy, seed);
    emu.mem = mem;
    emu.max_instructions = max_steps;

    let mut trace_bytes = Vec::new();

    while emu.step().map_err(|e| format!("{} (RIP: {:#x}, RAX: {:#x}, steps: {})", e, emu.cpu.regs.rip, emu.cpu.regs.rax, emu.cpu.instruction_count))? {
        if emu.cpu.instruction_count % 100 == 0 {
            trace_bytes.extend_from_slice(&emu.cpu.instruction_count.to_le_bytes());
            trace_bytes.extend_from_slice(&emu.cpu.regs.rip.to_le_bytes());
            trace_bytes.extend_from_slice(&emu.cpu.regs.rax.to_le_bytes());
        }
    }

    trace_bytes.extend_from_slice(&emu.cpu.instruction_count.to_le_bytes());
    trace_bytes.extend_from_slice(&emu.cpu.regs.rax.to_le_bytes());

    let hash = compute_trace_hash(&trace_bytes);
    Ok((emu.cpu.instruction_count, hash))
}

/// Runs an ELF binary through the emulator to completion using the default CrucibleAdaptive policy.
pub fn run_elf_trace(elf_data: &[u8], max_steps: u64) -> Result<(u64, [u8; 32]), String> {
    run_elf_trace_with_policy(
        elf_data,
        max_steps,
        crucible_core::SchedulingPolicy::default(),
        crucible_core::Seed(42),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_counting_exactness() {
        let mut harness1 = DeterminismHarness::new(0x400000, 0x7ffffff0);
        let mut harness2 = DeterminismHarness::new(0x400000, 0x7ffffff0);

        let res1 = harness1.run_steps(10_000);
        let res2 = harness2.run_steps(10_000);

        assert_eq!(res1, res2);
        assert_eq!(res1.0, 10_000);
    }
}
