//! CPU state, register file, and instruction execution engine for x86-64.

use crate::memory::VirtualMemory;
use iced_x86::{Instruction, OpKind, Register};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CpuRegisters {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub fs_base: u64,
    pub xmm: [[u64; 2]; 16],
}

impl CpuRegisters {
    // Standard RFLAGS bit definitions
    pub const CF: u64 = 1 << 0;
    pub const PF: u64 = 1 << 2;
    pub const ZF: u64 = 1 << 6;
    pub const SF: u64 = 1 << 7;
    pub const OF: u64 = 1 << 11;

    pub fn xmm_idx(reg: Register) -> Option<usize> {
        match reg {
            Register::XMM0 => Some(0),
            Register::XMM1 => Some(1),
            Register::XMM2 => Some(2),
            Register::XMM3 => Some(3),
            Register::XMM4 => Some(4),
            Register::XMM5 => Some(5),
            Register::XMM6 => Some(6),
            Register::XMM7 => Some(7),
            Register::XMM8 => Some(8),
            Register::XMM9 => Some(9),
            Register::XMM10 => Some(10),
            Register::XMM11 => Some(11),
            Register::XMM12 => Some(12),
            Register::XMM13 => Some(13),
            Register::XMM14 => Some(14),
            Register::XMM15 => Some(15),
            _ => None,
        }
    }

    pub fn get_xmm(&self, reg: Register) -> [u64; 2] {
        if let Some(idx) = Self::xmm_idx(reg) {
            self.xmm[idx]
        } else {
            [0, 0]
        }
    }

    pub fn set_xmm(&mut self, reg: Register, val: [u64; 2]) {
        if let Some(idx) = Self::xmm_idx(reg) {
            self.xmm[idx] = val;
        }
    }

    pub fn get_reg(&self, reg: Register) -> u64 {
        match reg {
            Register::RAX => self.rax,
            Register::EAX => self.rax as u32 as u64,
            Register::AX => self.rax as u16 as u64,
            Register::AL => self.rax as u8 as u64,

            Register::RBX => self.rbx,
            Register::EBX => self.rbx as u32 as u64,
            Register::BX => self.rbx as u16 as u64,
            Register::BL => self.rbx as u8 as u64,

            Register::RCX => self.rcx,
            Register::ECX => self.rcx as u32 as u64,
            Register::CX => self.rcx as u16 as u64,
            Register::CL => self.rcx as u8 as u64,

            Register::RDX => self.rdx,
            Register::EDX => self.rdx as u32 as u64,
            Register::DX => self.rdx as u16 as u64,
            Register::DL => self.rdx as u8 as u64,

            Register::RSI => self.rsi,
            Register::ESI => self.rsi as u32 as u64,
            Register::SI => self.rsi as u16 as u64,
            Register::SIL => self.rsi as u8 as u64,

            Register::RDI => self.rdi,
            Register::EDI => self.rdi as u32 as u64,
            Register::DI => self.rdi as u16 as u64,
            Register::DIL => self.rdi as u8 as u64,

            Register::RBP => self.rbp,
            Register::EBP => self.rbp as u32 as u64,
            Register::BP => self.rbp as u16 as u64,
            Register::BPL => self.rbp as u8 as u64,

            Register::RSP => self.rsp,
            Register::ESP => self.rsp as u32 as u64,

            Register::R8 => self.r8,
            Register::R8D => self.r8 as u32 as u64,
            Register::R8W => self.r8 as u16 as u64,
            Register::R8L => self.r8 as u8 as u64,

            Register::R9 => self.r9,
            Register::R9D => self.r9 as u32 as u64,
            Register::R9W => self.r9 as u16 as u64,
            Register::R9L => self.r9 as u8 as u64,

            Register::R10 => self.r10,
            Register::R10D => self.r10 as u32 as u64,
            Register::R10W => self.r10 as u16 as u64,
            Register::R10L => self.r10 as u8 as u64,

            Register::R11 => self.r11,
            Register::R11D => self.r11 as u32 as u64,
            Register::R11W => self.r11 as u16 as u64,
            Register::R11L => self.r11 as u8 as u64,

            Register::R12 => self.r12,
            Register::R12D => self.r12 as u32 as u64,
            Register::R12W => self.r12 as u16 as u64,
            Register::R12L => self.r12 as u8 as u64,

            Register::R13 => self.r13,
            Register::R13D => self.r13 as u32 as u64,
            Register::R13W => self.r13 as u16 as u64,
            Register::R13L => self.r13 as u8 as u64,

            Register::R14 => self.r14,
            Register::R14D => self.r14 as u32 as u64,
            Register::R14W => self.r14 as u16 as u64,
            Register::R14L => self.r14 as u8 as u64,

            Register::R15 => self.r15,
            Register::R15D => self.r15 as u32 as u64,
            Register::R15W => self.r15 as u16 as u64,
            Register::R15L => self.r15 as u8 as u64,

            Register::RIP => self.rip,
            _ => 0,
        }
    }

    pub fn set_reg(&mut self, reg: Register, val: u64) {
        match reg {
            Register::RAX => self.rax = val,
            Register::EAX => self.rax = val as u32 as u64,
            Register::AX => self.rax = (self.rax & !0xffff) | (val & 0xffff),
            Register::AL => self.rax = (self.rax & !0xff) | (val & 0xff),

            Register::RBX => self.rbx = val,
            Register::EBX => self.rbx = val as u32 as u64,
            Register::BX => self.rbx = (self.rbx & !0xffff) | (val & 0xffff),
            Register::BL => self.rbx = (self.rbx & !0xff) | (val & 0xff),

            Register::RCX => self.rcx = val,
            Register::ECX => self.rcx = val as u32 as u64,
            Register::CX => self.rcx = (self.rcx & !0xffff) | (val & 0xffff),
            Register::CL => self.rcx = (self.rcx & !0xff) | (val & 0xff),

            Register::RDX => self.rdx = val,
            Register::EDX => self.rdx = val as u32 as u64,
            Register::DX => self.rdx = (self.rdx & !0xffff) | (val & 0xffff),
            Register::DL => self.rdx = (self.rdx & !0xff) | (val & 0xff),

            Register::RSI => self.rsi = val,
            Register::ESI => self.rsi = val as u32 as u64,
            Register::SI => self.rsi = (self.rsi & !0xffff) | (val & 0xffff),
            Register::SIL => self.rsi = (self.rsi & !0xff) | (val & 0xff),

            Register::RDI => self.rdi = val,
            Register::EDI => self.rdi = val as u32 as u64,
            Register::DI => self.rdi = (self.rdi & !0xffff) | (val & 0xffff),
            Register::DIL => self.rdi = (self.rdi & !0xff) | (val & 0xff),

            Register::RBP => self.rbp = val,
            Register::EBP => self.rbp = val as u32 as u64,
            Register::BP => self.rbp = (self.rbp & !0xffff) | (val & 0xffff),
            Register::BPL => self.rbp = (self.rbp & !0xff) | (val & 0xff),

            Register::RSP => self.rsp = val,
            Register::ESP => self.rsp = val as u32 as u64,

            Register::R8 => self.r8 = val,
            Register::R8D => self.r8 = val as u32 as u64,
            Register::R8W => self.r8 = (self.r8 & !0xffff) | (val & 0xffff),
            Register::R8L => self.r8 = (self.r8 & !0xff) | (val & 0xff),

            Register::R9 => self.r9 = val,
            Register::R9D => self.r9 = val as u32 as u64,
            Register::R9W => self.r9 = (self.r9 & !0xffff) | (val & 0xffff),
            Register::R9L => self.r9 = (self.r9 & !0xff) | (val & 0xff),

            Register::R10 => self.r10 = val,
            Register::R10D => self.r10 = val as u32 as u64,
            Register::R10W => self.r10 = (self.r10 & !0xffff) | (val & 0xffff),
            Register::R10L => self.r10 = (self.r10 & !0xff) | (val & 0xff),

            Register::R11 => self.r11 = val,
            Register::R11D => self.r11 = val as u32 as u64,
            Register::R11W => self.r11 = (self.r11 & !0xffff) | (val & 0xffff),
            Register::R11L => self.r11 = (self.r11 & !0xff) | (val & 0xff),

            Register::R12 => self.r12 = val,
            Register::R12D => self.r12 = val as u32 as u64,
            Register::R12W => self.r12 = (self.r12 & !0xffff) | (val & 0xffff),
            Register::R12L => self.r12 = (self.r12 & !0xff) | (val & 0xff),

            Register::R13 => self.r13 = val,
            Register::R13D => self.r13 = val as u32 as u64,
            Register::R13W => self.r13 = (self.r13 & !0xffff) | (val & 0xffff),
            Register::R13L => self.r13 = (self.r13 & !0xff) | (val & 0xff),

            Register::R14 => self.r14 = val,
            Register::R14D => self.r14 = val as u32 as u64,
            Register::R14W => self.r14 = (self.r14 & !0xffff) | (val & 0xffff),
            Register::R14L => self.r14 = (self.r14 & !0xff) | (val & 0xff),

            Register::R15 => self.r15 = val,
            Register::R15D => self.r15 = val as u32 as u64,
            Register::R15W => self.r15 = (self.r15 & !0xffff) | (val & 0xffff),
            Register::R15L => self.r15 = (self.r15 & !0xff) | (val & 0xff),

            Register::RIP => self.rip = val,
            _ => {}
        }
    }
}

pub fn reg_size_bytes(reg: iced_x86::Register) -> usize {
    use iced_x86::Register::*;
    match reg {
        AL | CL | DL | BL | AH | CH | DH | BH | SPL | BPL | SIL | DIL
        | R8L | R9L | R10L | R11L | R12L | R13L | R14L | R15L => 1,
        AX | CX | DX | BX | SP | BP | SI | DI
        | R8W | R9W | R10W | R11W | R12W | R13W | R14W | R15W => 2,
        EAX | ECX | EDX | EBX | ESP | EBP | ESI | EDI
        | R8D | R9D | R10D | R11D | R12D | R13D | R14D | R15D => 4,
        RAX | RCX | RDX | RBX | RSP | RBP | RSI | RDI
        | R8 | R9 | R10 | R11 | R12 | R13 | R14 | R15 | RIP => 8,
        _ => 8,
    }
}

pub fn memory_size_bytes(size: iced_x86::MemorySize) -> usize {
    use iced_x86::MemorySize::*;
    match size {
        UInt8 | Int8 => 1,
        UInt16 | Int16 => 2,
        UInt32 | Int32 => 4,
        UInt64 | Int64 => 8,
        _ => 8,
    }
}

#[derive(Clone, Debug)]
pub struct VirtualCpu {
    pub regs: CpuRegisters,
    pub instruction_count: u64,
    pub halted: bool,
}

impl VirtualCpu {
    pub fn new(entry: u64, sp: u64) -> Self {
        let mut regs = CpuRegisters::default();
        regs.rip = entry;
        regs.rsp = sp;
        Self {
            regs,
            instruction_count: 0,
            halted: false,
        }
    }

    /// Read 128-bit XMM value from operand (register or memory)
    pub fn get_xmm_op(&self, instr: &Instruction, op_idx: u32, mem: &VirtualMemory) -> [u64; 2] {
        match instr.op_kind(op_idx) {
            OpKind::Register => self.regs.get_xmm(instr.op_register(op_idx)),
            OpKind::Memory => {
                let addr = self.eval_mem_addr(instr);
                let mut bytes = [0u8; 16];
                mem.read_bytes(addr, &mut bytes);
                let w0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                let w1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                [w0, w1]
            }
            _ => [0, 0],
        }
    }

    /// Write 128-bit XMM value to operand (register or memory)
    pub fn set_xmm_op(&mut self, instr: &Instruction, op_idx: u32, val: [u64; 2], mem: &mut VirtualMemory) {
        match instr.op_kind(op_idx) {
            OpKind::Register => {
                self.regs.set_xmm(instr.op_register(op_idx), val);
            }
            OpKind::Memory => {
                let addr = self.eval_mem_addr(instr);
                mem.write_bytes(addr, &val[0].to_le_bytes());
                mem.write_bytes(addr + 8, &val[1].to_le_bytes());
            }
            _ => {}
        }
    }

    /// Evaluates effective memory address of an operand
    pub fn get_op_size_bytes(&self, instr: &Instruction, op_idx: u32) -> usize {
        match instr.op_kind(op_idx) {
            OpKind::Register => reg_size_bytes(instr.op_register(op_idx)),
            OpKind::Memory => memory_size_bytes(instr.memory_size()),
            _ => 8,
        }
    }

    /// Evaluates effective memory address of an operand
    pub fn eval_mem_addr(&self, instr: &Instruction) -> u64 {
        if instr.is_ip_rel_memory_operand() {
            return instr.ip_rel_memory_address();
        }

        let mut addr = instr.memory_displacement64();
        if instr.segment_prefix() == Register::FS {
            addr = addr.wrapping_add(self.regs.fs_base);
        }
        if instr.memory_base() != Register::None {
            addr = addr.wrapping_add(self.regs.get_reg(instr.memory_base()));
        }
        if instr.memory_index() != Register::None {
            let idx = self.regs.get_reg(instr.memory_index());
            addr = addr.wrapping_add(idx.wrapping_mul(instr.memory_index_scale() as u64));
        }
        addr
    }

    /// Read value of an instruction operand
    pub fn get_op_val(&self, instr: &Instruction, op_idx: u32, mem: &VirtualMemory) -> u64 {
        match instr.op_kind(op_idx) {
            OpKind::Register => self.regs.get_reg(instr.op_register(op_idx)),
            OpKind::Immediate8 => instr.immediate8() as u64,
            OpKind::Immediate16 => instr.immediate16() as u64,
            OpKind::Immediate32 => instr.immediate32() as u64,
            OpKind::Immediate64 => instr.immediate64(),
            OpKind::Immediate8to16 => instr.immediate8to16() as u16 as u64,
            OpKind::Immediate8to32 => instr.immediate8to32() as u32 as u64,
            OpKind::Immediate8to64 => instr.immediate8to64() as u64,
            OpKind::Immediate32to64 => instr.immediate32to64() as u64,
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                instr.near_branch_target()
            }
            OpKind::Memory => {
                let addr = self.eval_mem_addr(instr);
                let size = memory_size_bytes(instr.memory_size());
                match size {
                    1 => mem.read_u8(addr).unwrap_or(0) as u64,
                    2 => mem.read_u16(addr).unwrap_or(0) as u64,
                    4 => mem.read_u32(addr).unwrap_or(0) as u64,
                    8 => mem.read_u64(addr).unwrap_or(0),
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    /// Write value to an instruction operand
    pub fn set_op_val(&mut self, instr: &Instruction, op_idx: u32, val: u64, mem: &mut VirtualMemory) {
        match instr.op_kind(op_idx) {
            OpKind::Register => {
                self.regs.set_reg(instr.op_register(op_idx), val);
            }
            OpKind::Memory => {
                let addr = self.eval_mem_addr(instr);
                let size = memory_size_bytes(instr.memory_size());
                match size {
                    1 => mem.write_u8(addr, val as u8),
                    2 => mem.write_u16(addr, val as u16),
                    4 => mem.write_u32(addr, val as u32),
                    8 => mem.write_u64(addr, val),
                    _ => {}
                }
            }
            _ => {}
        }
    }
}
