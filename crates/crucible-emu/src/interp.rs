//! x86-64 Instruction Interpreter & Syscall Dispatcher for Crucible.

use crate::cpu::{CpuRegisters, VirtualCpu};
use crate::memory::VirtualMemory;
use crucible_core::{CrucibleScheduler, SchedulingPolicy, Seed, SyncEvent, ThreadId};
use crucible_vkernel::{
    epoll_const, sys_nr, EpollWatchEntry, FileDescriptor, SocketAddrV4, SocketState,
    VirtualKernelContext,
};
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Mnemonic};

pub struct ExecutionTraceEntry {
    pub rip: u64,
    pub mnemonic: Mnemonic,
    pub instruction_count: u64,
}

#[derive(Debug, Clone)]
pub struct EmulatedThreadState {
    pub id: ThreadId,
    pub regs: CpuRegisters,
    pub is_blocked: bool,
    pub halted: bool,
}

fn xmm_to_bytes(v: [u64; 2]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&v[0].to_le_bytes());
    b[8..16].copy_from_slice(&v[1].to_le_bytes());
    b
}

fn bytes_to_xmm(b: [u8; 16]) -> [u64; 2] {
    let w0 = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let w1 = u64::from_le_bytes(b[8..16].try_into().unwrap());
    [w0, w1]
}

pub struct Emulator {
    pub cpu: VirtualCpu,
    pub current_thread_idx: usize,
    pub threads: Vec<EmulatedThreadState>,
    pub scheduler: CrucibleScheduler,
    pub mem: VirtualMemory,
    pub vkernel: VirtualKernelContext,
    pub trace_log: Vec<ExecutionTraceEntry>,
    pub max_instructions: u64,
    pub decode_cache: std::collections::HashMap<u64, Instruction>,
}

impl Emulator {
    pub fn new(entry: u64, sp: u64) -> Self {
        let cpu = VirtualCpu::new(entry, sp);
        let initial_thread = EmulatedThreadState {
            id: ThreadId(1000),
            regs: cpu.regs,
            is_blocked: false,
            halted: false,
        };
        let mut scheduler = CrucibleScheduler::new(
            SchedulingPolicy::default(),
            Seed(42),
            10_000_000,
        );
        scheduler.register_thread(ThreadId(1000));

        Self {
            cpu,
            current_thread_idx: 0,
            threads: vec![initial_thread],
            scheduler,
            mem: VirtualMemory::new(),
            vkernel: VirtualKernelContext::default(),
            trace_log: Vec::new(),
            max_instructions: 10_000_000,
            decode_cache: std::collections::HashMap::new(),
        }
    }

    pub fn with_policy(mut self, policy: SchedulingPolicy, seed: Seed) -> Self {
        self.scheduler = CrucibleScheduler::new(policy, seed, self.max_instructions);
        for t in &self.threads {
            self.scheduler.register_thread(t.id);
        }
        self
    }

    pub fn schedule_next_thread(&mut self) -> bool {
        if self.threads.is_empty() {
            return false;
        }
        self.threads[self.current_thread_idx].regs = self.cpu.regs;
        if self.cpu.halted {
            self.threads[self.current_thread_idx].halted = true;
            self.scheduler.mark_halted(self.threads[self.current_thread_idx].id);
        }
        if self.threads[self.current_thread_idx].is_blocked {
            self.scheduler.mark_blocked(self.threads[self.current_thread_idx].id);
        }

        if !self.scheduler.schedule_next() {
            return false;
        }

        self.current_thread_idx = self.scheduler.current_thread_idx;
        self.cpu.regs = self.threads[self.current_thread_idx].regs;
        self.cpu.halted = self.threads[self.current_thread_idx].halted;
        true
    }

    /// Step a single instruction
    pub fn step(&mut self) -> Result<bool, String> {
        if self.cpu.halted || self.threads[self.current_thread_idx].is_blocked {
            if !self.schedule_next_thread() {
                return Ok(false);
            }
        }

        if self.cpu.instruction_count >= self.max_instructions {
            return Err("Execution exceeded instruction limit".to_string());
        }

        let need_switch = self.scheduler.step();
        if need_switch && self.threads.len() > 1 {
            self.schedule_next_thread();
        }

        // Fetch and decode instruction at RIP (using decode cache for speed)
        let rip = self.cpu.regs.rip;
        if rip == 0 {
            self.cpu.halted = true;
            return Ok(false);
        }

        let instr = if let Some(&cached) = self.decode_cache.get(&rip) {
            cached
        } else {
            let mut bytes = [0u8; 15];
            if !self.mem.read_bytes(rip, &mut bytes) {
                let history: Vec<String> = self.trace_log.iter().rev().take(10).map(|e| format!("{:#x}: {:?}", e.rip, e.mnemonic)).collect();
                return Err(format!("Instruction fetch fault at RIP {:#x}. History: {:?}", rip, history));
            }

            let mut decoder = Decoder::with_ip(64, &bytes, rip, DecoderOptions::NONE);
            let mut decoded = Instruction::default();
            decoder.decode_out(&mut decoded);

            if decoded.is_invalid() {
                return Err(format!("Invalid instruction at RIP {:#x}: {:02x?}", rip, &bytes[..4]));
            }
            self.decode_cache.insert(rip, decoded);
            decoded
        };

        let instr_len = instr.len() as u64;
        let next_rip = rip + instr_len;

        // Default advance RIP to next instruction
        self.cpu.regs.rip = next_rip;
        self.cpu.instruction_count += 1;
        self.vkernel.virtual_time.0 += 10;
        self.trace_log.push(ExecutionTraceEntry {
            rip,
            mnemonic: instr.mnemonic(),
            instruction_count: self.cpu.instruction_count,
        });

        match instr.mnemonic() {
            Mnemonic::Cdqe => {
                self.cpu.regs.rax = (self.cpu.regs.rax as i32 as i64) as u64;
            }
            Mnemonic::Cdq => {
                if (self.cpu.regs.rax as i32) < 0 {
                    self.cpu.regs.rdx = 0xffffffff;
                } else {
                    self.cpu.regs.rdx = 0;
                }
            }
            Mnemonic::Cwd => {
                let ax = (self.cpu.regs.rax as i16) as i32;
                if ax < 0 {
                    self.cpu.regs.rdx = (self.cpu.regs.rdx & !0xffff) | 0xffff;
                } else {
                    self.cpu.regs.rdx &= !0xffff;
                }
            }
            Mnemonic::Cqo => {
                if (self.cpu.regs.rax as i64) < 0 {
                    self.cpu.regs.rdx = u64::MAX;
                } else {
                    self.cpu.regs.rdx = 0;
                }
            }
            Mnemonic::Shl => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let shift = (self.cpu.get_op_val(&instr, 1, &self.mem) & 0x3f) as u32;
                let res = match size {
                    1 => (dst as u8).wrapping_shl(shift) as u64,
                    2 => (dst as u16).wrapping_shl(shift) as u64,
                    4 => (dst as u32).wrapping_shl(shift) as u64,
                    _ => dst.wrapping_shl(shift),
                };
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                self.update_logic_flags(res, size);
            }
            Mnemonic::Shr => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let shift = (self.cpu.get_op_val(&instr, 1, &self.mem) & 0x3f) as u32;
                let res = match size {
                    1 => ((dst as u8) >> shift) as u64,
                    2 => ((dst as u16) >> shift) as u64,
                    4 => ((dst as u32) >> shift) as u64,
                    _ => dst.wrapping_shr(shift),
                };
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                self.update_logic_flags(res, size);
            }
            Mnemonic::Sar => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let shift = (self.cpu.get_op_val(&instr, 1, &self.mem) & 0x3f) as u32;
                let res = match size {
                    1 => ((dst as i8) >> shift) as u8 as u64,
                    2 => ((dst as i16) >> shift) as u16 as u64,
                    4 => ((dst as i32) >> shift) as u32 as u64,
                    _ => ((dst as i64) >> shift) as u64,
                };
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                self.update_logic_flags(res, size);
            }
            Mnemonic::Neg => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let res = self.eval_sub_flags(0, dst, size);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Not => {
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let res = !dst;
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Imul => {
                let op_count = instr.op_count();
                if op_count == 2 {
                    let dst = self.cpu.get_op_val(&instr, 0, &self.mem) as i64;
                    let src = self.cpu.get_op_val(&instr, 1, &self.mem) as i64;
                    let res = (dst.wrapping_mul(src)) as u64;
                    self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                } else if op_count == 3 {
                    let src1 = self.cpu.get_op_val(&instr, 1, &self.mem) as i64;
                    let src2 = self.cpu.get_op_val(&instr, 2, &self.mem) as i64;
                    let res = (src1.wrapping_mul(src2)) as u64;
                    self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                }
            }
            Mnemonic::Mul => {
                let src = self.cpu.get_op_val(&instr, 0, &self.mem);
                let prod = (self.cpu.regs.rax as u128) * (src as u128);
                self.cpu.regs.rax = prod as u64;
                self.cpu.regs.rdx = (prod >> 64) as u64;
                if self.cpu.regs.rdx != 0 {
                    self.cpu.regs.rflags |= CpuRegisters::CF | CpuRegisters::OF;
                } else {
                    self.cpu.regs.rflags &= !(CpuRegisters::CF | CpuRegisters::OF);
                }
            }
            Mnemonic::Div => {
                let divisor = self.cpu.get_op_val(&instr, 0, &self.mem);
                if divisor != 0 {
                    let dividend = ((self.cpu.regs.rdx as u128) << 64) | (self.cpu.regs.rax as u128);
                    let quot = dividend / (divisor as u128);
                    let rem = dividend % (divisor as u128);
                    self.cpu.regs.rax = quot as u64;
                    self.cpu.regs.rdx = rem as u64;
                }
            }
            Mnemonic::Idiv => {
                let divisor = self.cpu.get_op_val(&instr, 0, &self.mem) as i64;
                if divisor != 0 {
                    let dividend = (((self.cpu.regs.rdx as i128) << 64) | (self.cpu.regs.rax as i128)) as i128;
                    let quot = dividend / (divisor as i128);
                    let rem = dividend % (divisor as i128);
                    self.cpu.regs.rax = quot as i64 as u64;
                    self.cpu.regs.rdx = rem as i64 as u64;
                }
            }
            Mnemonic::Sete => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setne => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::ZF) == 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setb => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setae => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::CF) == 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setl => {
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                let cond = sf != of;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setge => {
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                let cond = sf == of;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setg => {
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                let cond = !zf && (sf == of);
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setle => {
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                let cond = zf || (sf != of);
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setbe => {
                let cf = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let cond = cf || zf;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Seta => {
                let cf = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let cond = !cf && !zf;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Sets => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setns => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::SF) == 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setp => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::PF) != 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setnp => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::PF) == 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Seto => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Setno => {
                let cond = (self.cpu.regs.rflags & CpuRegisters::OF) == 0;
                self.cpu.set_op_val(&instr, 0, cond as u64, &mut self.mem);
            }
            Mnemonic::Cmpxchg => {
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let acc = self.cpu.regs.rax;

                if dst == acc {
                    self.cpu.set_op_val(&instr, 0, src, &mut self.mem);
                    self.cpu.regs.rflags |= CpuRegisters::ZF;
                } else {
                    self.cpu.regs.rax = dst;
                    self.cpu.regs.rflags &= !CpuRegisters::ZF;
                }
            }
            Mnemonic::Cld => {
                self.cpu.regs.rflags &= !(1 << 10);
            }
            Mnemonic::Std => {
                self.cpu.regs.rflags |= 1 << 10;
            }
            Mnemonic::Xorps | Mnemonic::Pxor => {
                let v1 = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let v2 = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [v1[0] ^ v2[0], v1[1] ^ v2[1]], &mut self.mem);
            }
            Mnemonic::Por | Mnemonic::Orps | Mnemonic::Orpd => {
                let v1 = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let v2 = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [v1[0] | v2[0], v1[1] | v2[1]], &mut self.mem);
            }
            Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd => {
                let v1 = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let v2 = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [v1[0] & v2[0], v1[1] & v2[1]], &mut self.mem);
            }
            Mnemonic::Pandn | Mnemonic::Andnps | Mnemonic::Andnpd => {
                let v1 = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let v2 = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [(!v1[0]) & v2[0], (!v1[1]) & v2[1]], &mut self.mem);
            }
            Mnemonic::Ptest | Mnemonic::Vptest => {
                let s1 = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s2 = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.regs.rflags &= !(CpuRegisters::ZF | CpuRegisters::CF | CpuRegisters::OF | CpuRegisters::SF | CpuRegisters::PF);
                if ((s2[0] & s1[0]) == 0) && ((s2[1] & s1[1]) == 0) {
                    self.cpu.regs.rflags |= CpuRegisters::ZF;
                }
                if ((s2[0] & !s1[0]) == 0) && ((s2[1] & !s1[1]) == 0) {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                }
            }
            Mnemonic::Vpshufd => {
                let src = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                let imm = instr.immediate8();
                let dw = [
                    src[0] as u32,
                    (src[0] >> 32) as u32,
                    src[1] as u32,
                    (src[1] >> 32) as u32,
                ];
                let res_dw = [
                    dw[((imm >> 0) & 3) as usize],
                    dw[((imm >> 2) & 3) as usize],
                    dw[((imm >> 4) & 3) as usize],
                    dw[((imm >> 6) & 3) as usize],
                ];
                let w0 = (res_dw[0] as u64) | ((res_dw[1] as u64) << 32);
                let w1 = (res_dw[2] as u64) | ((res_dw[3] as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Palignr | Mnemonic::Vpalignr => {
                let (d, s, imm) = if instr.op_count() == 4 {
                    (xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem)), xmm_to_bytes(self.cpu.get_xmm_op(&instr, 2, &self.mem)), instr.immediate8() as usize)
                } else {
                    (xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem)), xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem)), instr.immediate8() as usize)
                };
                let mut concat = [0u8; 32];
                concat[..16].copy_from_slice(&s);
                concat[16..].copy_from_slice(&d);
                let mut res = [0u8; 16];
                if imm < 32 {
                    let end = (imm + 16).min(32);
                    res[..end - imm].copy_from_slice(&concat[imm..end]);
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(res), &mut self.mem);
            }
            Mnemonic::Vzeroupper | Mnemonic::Vzeroall => {}
            Mnemonic::Vpbroadcastb => {
                let byte = if instr.op_kind(1) == iced_x86::OpKind::Register {
                    if CpuRegisters::xmm_idx(instr.op_register(1)).is_some() {
                        (self.cpu.regs.get_xmm(instr.op_register(1))[0] & 0xFF) as u8
                    } else {
                        (self.cpu.regs.get_reg(instr.op_register(1)) & 0xFF) as u8
                    }
                } else {
                    self.mem.read_u8(self.cpu.eval_mem_addr(&instr)).unwrap_or(0)
                };
                let res = [byte; 16];
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(res), &mut self.mem);
            }
            Mnemonic::Vpbroadcastw => {
                let word = if instr.op_kind(1) == iced_x86::OpKind::Register {
                    if CpuRegisters::xmm_idx(instr.op_register(1)).is_some() {
                        (self.cpu.regs.get_xmm(instr.op_register(1))[0] & 0xFFFF) as u16
                    } else {
                        (self.cpu.regs.get_reg(instr.op_register(1)) & 0xFFFF) as u16
                    }
                } else {
                    self.mem.read_u16(self.cpu.eval_mem_addr(&instr)).unwrap_or(0)
                };
                let w = word as u64;
                let q = w | (w << 16) | (w << 32) | (w << 48);
                self.cpu.set_xmm_op(&instr, 0, [q, q], &mut self.mem);
            }
            Mnemonic::Vpbroadcastd => {
                let dword = if instr.op_kind(1) == iced_x86::OpKind::Register {
                    if CpuRegisters::xmm_idx(instr.op_register(1)).is_some() {
                        (self.cpu.regs.get_xmm(instr.op_register(1))[0] & 0xFFFFFFFF) as u32
                    } else {
                        (self.cpu.regs.get_reg(instr.op_register(1)) & 0xFFFFFFFF) as u32
                    }
                } else {
                    self.mem.read_u32(self.cpu.eval_mem_addr(&instr)).unwrap_or(0)
                };
                let d = dword as u64;
                let q = d | (d << 32);
                self.cpu.set_xmm_op(&instr, 0, [q, q], &mut self.mem);
            }
            Mnemonic::Vpbroadcastq => {
                let qword = if instr.op_kind(1) == iced_x86::OpKind::Register {
                    if CpuRegisters::xmm_idx(instr.op_register(1)).is_some() {
                        self.cpu.regs.get_xmm(instr.op_register(1))[0]
                    } else {
                        self.cpu.regs.get_reg(instr.op_register(1))
                    }
                } else {
                    self.mem.read_u64(self.cpu.eval_mem_addr(&instr)).unwrap_or(0)
                };
                self.cpu.set_xmm_op(&instr, 0, [qword, qword], &mut self.mem);
            }
            Mnemonic::Vpxor => {
                let (s1, s2) = if instr.op_count() == 3 {
                    (self.cpu.get_xmm_op(&instr, 1, &self.mem), self.cpu.get_xmm_op(&instr, 2, &self.mem))
                } else {
                    (self.cpu.get_xmm_op(&instr, 0, &self.mem), self.cpu.get_xmm_op(&instr, 1, &self.mem))
                };
                self.cpu.set_xmm_op(&instr, 0, [s1[0] ^ s2[0], s1[1] ^ s2[1]], &mut self.mem);
            }
            Mnemonic::Vpor => {
                let (s1, s2) = if instr.op_count() == 3 {
                    (self.cpu.get_xmm_op(&instr, 1, &self.mem), self.cpu.get_xmm_op(&instr, 2, &self.mem))
                } else {
                    (self.cpu.get_xmm_op(&instr, 0, &self.mem), self.cpu.get_xmm_op(&instr, 1, &self.mem))
                };
                self.cpu.set_xmm_op(&instr, 0, [s1[0] | s2[0], s1[1] | s2[1]], &mut self.mem);
            }
            Mnemonic::Vpand => {
                let (s1, s2) = if instr.op_count() == 3 {
                    (self.cpu.get_xmm_op(&instr, 1, &self.mem), self.cpu.get_xmm_op(&instr, 2, &self.mem))
                } else {
                    (self.cpu.get_xmm_op(&instr, 0, &self.mem), self.cpu.get_xmm_op(&instr, 1, &self.mem))
                };
                self.cpu.set_xmm_op(&instr, 0, [s1[0] & s2[0], s1[1] & s2[1]], &mut self.mem);
            }
            Mnemonic::Vmovdqu | Mnemonic::Vmovdqa | Mnemonic::Vmovups | Mnemonic::Vmovaps => {
                let val = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, val, &mut self.mem);
            }
            Mnemonic::Vpcmpeqb => {
                let (d, s) = if instr.op_count() == 3 {
                    (xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem)), xmm_to_bytes(self.cpu.get_xmm_op(&instr, 2, &self.mem)))
                } else {
                    (xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem)), xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem)))
                };
                let mut r = [0u8; 16];
                for i in 0..16 {
                    r[i] = if d[i] == s[i] { 0xFF } else { 0x00 };
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Vpmovmskb => {
                let src = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut mask = 0u32;
                for i in 0..16 {
                    if (src[i] & 0x80) != 0 {
                        mask |= 1 << i;
                    }
                }
                self.cpu.set_op_val(&instr, 0, mask as u64, &mut self.mem);
            }
            Mnemonic::Punpcklbw => {
                let d = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let s = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut r = [0u8; 16];
                for i in 0..8 {
                    r[2 * i] = d[i];
                    r[2 * i + 1] = s[i];
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Punpckhbw => {
                let d = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let s = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut r = [0u8; 16];
                for i in 0..8 {
                    r[2 * i] = d[8 + i];
                    r[2 * i + 1] = s[8 + i];
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Punpcklwd => {
                let d = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let s = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut r = [0u8; 16];
                for i in 0..4 {
                    r[4 * i..4 * i + 2].copy_from_slice(&d[2 * i..2 * i + 2]);
                    r[4 * i + 2..4 * i + 4].copy_from_slice(&s[2 * i..2 * i + 2]);
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Punpckhwd => {
                let d = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let s = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut r = [0u8; 16];
                for i in 0..4 {
                    r[4 * i..4 * i + 2].copy_from_slice(&d[8 + 2 * i..8 + 2 * i + 2]);
                    r[4 * i + 2..4 * i + 4].copy_from_slice(&s[8 + 2 * i..8 + 2 * i + 2]);
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Punpckldq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                let d0 = d[0] as u32;
                let d1 = (d[0] >> 32) as u32;
                let s0 = s[0] as u32;
                let s1 = (s[0] >> 32) as u32;
                let w0 = (d0 as u64) | ((s0 as u64) << 32);
                let w1 = (d1 as u64) | ((s1 as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Punpckhdq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                let d2 = d[1] as u32;
                let d3 = (d[1] >> 32) as u32;
                let s2 = s[1] as u32;
                let s3 = (s[1] >> 32) as u32;
                let w0 = (d2 as u64) | ((s2 as u64) << 32);
                let w1 = (d3 as u64) | ((s3 as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Punpcklqdq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [d[0], s[0]], &mut self.mem);
            }
            Mnemonic::Punpckhqdq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [d[1], s[1]], &mut self.mem);
            }
            Mnemonic::Pshufd => {
                let src = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                let imm = instr.immediate8();
                let dw = [
                    src[0] as u32,
                    (src[0] >> 32) as u32,
                    src[1] as u32,
                    (src[1] >> 32) as u32,
                ];
                let res_dw = [
                    dw[((imm >> 0) & 3) as usize],
                    dw[((imm >> 2) & 3) as usize],
                    dw[((imm >> 4) & 3) as usize],
                    dw[((imm >> 6) & 3) as usize],
                ];
                let w0 = (res_dw[0] as u64) | ((res_dw[1] as u64) << 32);
                let w1 = (res_dw[2] as u64) | ((res_dw[3] as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Pshufb => {
                let d = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let mask = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut r = [0u8; 16];
                for i in 0..16 {
                    if (mask[i] & 0x80) != 0 {
                        r[i] = 0;
                    } else {
                        r[i] = d[(mask[i] & 0x0f) as usize];
                    }
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Pmovmskb => {
                let src = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut mask = 0u32;
                for i in 0..16 {
                    if (src[i] & 0x80) != 0 {
                        mask |= 1 << i;
                    }
                }
                self.cpu.set_op_val(&instr, 0, mask as u64, &mut self.mem);
            }
            Mnemonic::Pcmpeqb => {
                let d = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let s = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 1, &self.mem));
                let mut r = [0u8; 16];
                for i in 0..16 {
                    r[i] = if d[i] == s[i] { 0xFF } else { 0x00 };
                }
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(r), &mut self.mem);
            }
            Mnemonic::Pcmpeqd => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                let d_dw = [d[0] as u32, (d[0] >> 32) as u32, d[1] as u32, (d[1] >> 32) as u32];
                let s_dw = [s[0] as u32, (s[0] >> 32) as u32, s[1] as u32, (s[1] >> 32) as u32];
                let r_dw = [
                    if d_dw[0] == s_dw[0] { 0xFFFFFFFFu32 } else { 0 },
                    if d_dw[1] == s_dw[1] { 0xFFFFFFFFu32 } else { 0 },
                    if d_dw[2] == s_dw[2] { 0xFFFFFFFFu32 } else { 0 },
                    if d_dw[3] == s_dw[3] { 0xFFFFFFFFu32 } else { 0 },
                ];
                let w0 = (r_dw[0] as u64) | ((r_dw[1] as u64) << 32);
                let w1 = (r_dw[2] as u64) | ((r_dw[3] as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Paddq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                self.cpu.set_xmm_op(&instr, 0, [d[0].wrapping_add(s[0]), d[1].wrapping_add(s[1])], &mut self.mem);
            }
            Mnemonic::Paddd => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let s = self.cpu.get_xmm_op(&instr, 1, &self.mem);
                let d_dw = [d[0] as u32, (d[0] >> 32) as u32, d[1] as u32, (d[1] >> 32) as u32];
                let s_dw = [s[0] as u32, (s[0] >> 32) as u32, s[1] as u32, (s[1] >> 32) as u32];
                let r0 = d_dw[0].wrapping_add(s_dw[0]);
                let r1 = d_dw[1].wrapping_add(s_dw[1]);
                let r2 = d_dw[2].wrapping_add(s_dw[2]);
                let r3 = d_dw[3].wrapping_add(s_dw[3]);
                let w0 = (r0 as u64) | ((r1 as u64) << 32);
                let w1 = (r2 as u64) | ((r3 as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Pslld => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let shift = if instr.op_kind(1) == iced_x86::OpKind::Immediate8 {
                    instr.immediate8() as u32
                } else {
                    self.cpu.get_xmm_op(&instr, 1, &self.mem)[0] as u32
                };
                let mut d_dw = [d[0] as u32, (d[0] >> 32) as u32, d[1] as u32, (d[1] >> 32) as u32];
                for dw in &mut d_dw {
                    *dw = if shift >= 32 { 0 } else { *dw << shift };
                }
                let w0 = (d_dw[0] as u64) | ((d_dw[1] as u64) << 32);
                let w1 = (d_dw[2] as u64) | ((d_dw[3] as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Psrld => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let shift = if instr.op_kind(1) == iced_x86::OpKind::Immediate8 {
                    instr.immediate8() as u32
                } else {
                    self.cpu.get_xmm_op(&instr, 1, &self.mem)[0] as u32
                };
                let mut d_dw = [d[0] as u32, (d[0] >> 32) as u32, d[1] as u32, (d[1] >> 32) as u32];
                for dw in &mut d_dw {
                    *dw = if shift >= 32 { 0 } else { *dw >> shift };
                }
                let w0 = (d_dw[0] as u64) | ((d_dw[1] as u64) << 32);
                let w1 = (d_dw[2] as u64) | ((d_dw[3] as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Psrad => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let shift = if instr.op_kind(1) == iced_x86::OpKind::Immediate8 {
                    instr.immediate8() as u32
                } else {
                    self.cpu.get_xmm_op(&instr, 1, &self.mem)[0] as u32
                };
                let mut d_dw = [d[0] as u32, (d[0] >> 32) as u32, d[1] as u32, (d[1] >> 32) as u32];
                for dw in &mut d_dw {
                    let s = *dw as i32;
                    *dw = if shift >= 32 { if s < 0 { 0xFFFFFFFF } else { 0 } } else { (s >> shift) as u32 };
                }
                let w0 = (d_dw[0] as u64) | ((d_dw[1] as u64) << 32);
                let w1 = (d_dw[2] as u64) | ((d_dw[3] as u64) << 32);
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Psllq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let shift = if instr.op_kind(1) == iced_x86::OpKind::Immediate8 {
                    instr.immediate8() as u32
                } else {
                    self.cpu.get_xmm_op(&instr, 1, &self.mem)[0] as u32
                };
                let w0 = if shift >= 64 { 0 } else { d[0] << shift };
                let w1 = if shift >= 64 { 0 } else { d[1] << shift };
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Psrlq => {
                let d = self.cpu.get_xmm_op(&instr, 0, &self.mem);
                let shift = if instr.op_kind(1) == iced_x86::OpKind::Immediate8 {
                    instr.immediate8() as u32
                } else {
                    self.cpu.get_xmm_op(&instr, 1, &self.mem)[0] as u32
                };
                let w0 = if shift >= 64 { 0 } else { d[0] >> shift };
                let w1 = if shift >= 64 { 0 } else { d[1] >> shift };
                self.cpu.set_xmm_op(&instr, 0, [w0, w1], &mut self.mem);
            }
            Mnemonic::Pslldq => {
                let bytes = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let shift = (instr.immediate8() as usize).min(16);
                let mut res = [0u8; 16];
                res[shift..].copy_from_slice(&bytes[..16 - shift]);
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(res), &mut self.mem);
            }
            Mnemonic::Psrldq => {
                let bytes = xmm_to_bytes(self.cpu.get_xmm_op(&instr, 0, &self.mem));
                let shift = (instr.immediate8() as usize).min(16);
                let mut res = [0u8; 16];
                res[..16 - shift].copy_from_slice(&bytes[shift..]);
                self.cpu.set_xmm_op(&instr, 0, bytes_to_xmm(res), &mut self.mem);
            }
            Mnemonic::Bt => {
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                let bit = (self.cpu.get_op_val(&instr, 1, &self.mem) & 63) as u32;
                if ((val >> bit) & 1) != 0 {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                } else {
                    self.cpu.regs.rflags &= !CpuRegisters::CF;
                }
            }
            Mnemonic::Bts => {
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                let bit = (self.cpu.get_op_val(&instr, 1, &self.mem) & 63) as u32;
                if ((val >> bit) & 1) != 0 {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                } else {
                    self.cpu.regs.rflags &= !CpuRegisters::CF;
                }
                let res = val | (1 << bit);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Btr => {
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                let bit = (self.cpu.get_op_val(&instr, 1, &self.mem) & 63) as u32;
                if ((val >> bit) & 1) != 0 {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                } else {
                    self.cpu.regs.rflags &= !CpuRegisters::CF;
                }
                let res = val & !(1 << bit);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Bsf | Mnemonic::Tzcnt => {
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                if src == 0 {
                    self.cpu.regs.rflags |= CpuRegisters::ZF | CpuRegisters::CF;
                    self.cpu.set_op_val(&instr, 0, 64, &mut self.mem);
                } else {
                    self.cpu.regs.rflags &= !(CpuRegisters::ZF | CpuRegisters::CF);
                    let count = src.trailing_zeros() as u64;
                    self.cpu.set_op_val(&instr, 0, count, &mut self.mem);
                }
            }
            Mnemonic::Bsr | Mnemonic::Lzcnt => {
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                if src == 0 {
                    self.cpu.regs.rflags |= CpuRegisters::ZF;
                } else {
                    self.cpu.regs.rflags &= !CpuRegisters::ZF;
                    let count = 63 - (src.leading_zeros() as u64);
                    self.cpu.set_op_val(&instr, 0, count, &mut self.mem);
                }
            }
            Mnemonic::Popcnt => {
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let count = src.count_ones() as u64;
                self.cpu.set_op_val(&instr, 0, count, &mut self.mem);
                if count == 0 {
                    self.cpu.regs.rflags |= CpuRegisters::ZF;
                } else {
                    self.cpu.regs.rflags &= !CpuRegisters::ZF;
                }
            }
            Mnemonic::Stosb => {
                if instr.has_rep_prefix() {
                    let df = (self.cpu.regs.rflags & (1 << 10)) != 0;
                    let val = self.cpu.regs.rax as u8;
                    while self.cpu.regs.rcx > 0 {
                        self.mem.write_u8(self.cpu.regs.rdi, val);
                        if df { self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_sub(1); }
                        else { self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(1); }
                        self.cpu.regs.rcx -= 1;
                    }
                } else {
                    let val = self.cpu.regs.rax as u8;
                    self.mem.write_u8(self.cpu.regs.rdi, val);
                    self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(1);
                }
            }
            Mnemonic::Stosq => {
                if instr.has_rep_prefix() {
                    let df = (self.cpu.regs.rflags & (1 << 10)) != 0;
                    let val = self.cpu.regs.rax;
                    while self.cpu.regs.rcx > 0 {
                        self.mem.write_u64(self.cpu.regs.rdi, val);
                        if df { self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_sub(8); }
                        else { self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(8); }
                        self.cpu.regs.rcx -= 1;
                    }
                } else {
                    let val = self.cpu.regs.rax;
                    self.mem.write_u64(self.cpu.regs.rdi, val);
                    self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(8);
                }
            }
            Mnemonic::Movsb => {
                if instr.has_rep_prefix() {
                    let df = (self.cpu.regs.rflags & (1 << 10)) != 0;
                    while self.cpu.regs.rcx > 0 {
                        let b = self.mem.read_u8(self.cpu.regs.rsi).unwrap_or(0);
                        self.mem.write_u8(self.cpu.regs.rdi, b);
                        if df {
                            self.cpu.regs.rsi = self.cpu.regs.rsi.wrapping_sub(1);
                            self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_sub(1);
                        } else {
                            self.cpu.regs.rsi = self.cpu.regs.rsi.wrapping_add(1);
                            self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(1);
                        }
                        self.cpu.regs.rcx -= 1;
                    }
                } else {
                    let b = self.mem.read_u8(self.cpu.regs.rsi).unwrap_or(0);
                    self.mem.write_u8(self.cpu.regs.rdi, b);
                    self.cpu.regs.rsi = self.cpu.regs.rsi.wrapping_add(1);
                    self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(1);
                }
            }
            Mnemonic::Movsq => {
                if instr.has_rep_prefix() {
                    let df = (self.cpu.regs.rflags & (1 << 10)) != 0;
                    while self.cpu.regs.rcx > 0 {
                        let q = self.mem.read_u64(self.cpu.regs.rsi).unwrap_or(0);
                        self.mem.write_u64(self.cpu.regs.rdi, q);
                        if df {
                            self.cpu.regs.rsi = self.cpu.regs.rsi.wrapping_sub(8);
                            self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_sub(8);
                        } else {
                            self.cpu.regs.rsi = self.cpu.regs.rsi.wrapping_add(8);
                            self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(8);
                        }
                        self.cpu.regs.rcx -= 1;
                    }
                } else {
                    let q = self.mem.read_u64(self.cpu.regs.rsi).unwrap_or(0);
                    self.mem.write_u64(self.cpu.regs.rdi, q);
                    self.cpu.regs.rsi = self.cpu.regs.rsi.wrapping_add(8);
                    self.cpu.regs.rdi = self.cpu.regs.rdi.wrapping_add(8);
                }
            }
            Mnemonic::Pause | Mnemonic::Mfence | Mnemonic::Lfence | Mnemonic::Sfence
            | Mnemonic::Prefetcht0 | Mnemonic::Prefetcht1 | Mnemonic::Prefetcht2 | Mnemonic::Prefetchnta => {}
            Mnemonic::Ucomisd | Mnemonic::Ucomiss => {
                let v1_bits = self.cpu.regs.get_xmm(instr.op_register(0))[0];
                let v1 = f64::from_bits(v1_bits);
                let v2_bits = match instr.op_kind(1) {
                    iced_x86::OpKind::Register => {
                        self.cpu.regs.get_xmm(instr.op_register(1))[0]
                    }
                    iced_x86::OpKind::Memory => {
                        let addr = self.cpu.eval_mem_addr(&instr);
                        self.mem.read_u64(addr).unwrap_or(0)
                    }
                    _ => 0,
                };
                let v2 = f64::from_bits(v2_bits);
                self.cpu.regs.rflags &= !(CpuRegisters::ZF | CpuRegisters::CF | CpuRegisters::PF | CpuRegisters::OF | CpuRegisters::SF);
                if v1.is_nan() || v2.is_nan() {
                    // Unordered: ZF=1, PF=1, CF=1
                    self.cpu.regs.rflags |= CpuRegisters::ZF | CpuRegisters::PF | CpuRegisters::CF;
                } else if v1 == v2 {
                    self.cpu.regs.rflags |= CpuRegisters::ZF;
                } else if v1 < v2 {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                }
            }
            Mnemonic::Cvtsi2sd => {
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let f_bits = (src as i64 as f64).to_bits();
                let mut xmm = self.cpu.regs.get_xmm(instr.op_register(0));
                xmm[0] = f_bits;
                self.cpu.regs.set_xmm(instr.op_register(0), xmm);
            }
            Mnemonic::Cvtsi2ss => {
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let f_bits = (src as i64 as f32).to_bits() as u64;
                let mut xmm = self.cpu.regs.get_xmm(instr.op_register(0));
                xmm[0] = f_bits;
                self.cpu.regs.set_xmm(instr.op_register(0), xmm);
            }
            Mnemonic::Cvttsd2si => {
                let src_bits = match instr.op_kind(1) {
                    iced_x86::OpKind::Register => self.cpu.regs.get_xmm(instr.op_register(1))[0],
                    iced_x86::OpKind::Memory => self.mem.read_u64(self.cpu.eval_mem_addr(&instr)).unwrap_or(0),
                    _ => 0,
                };
                let val = (f64::from_bits(src_bits) as i64) as u64;
                self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
            }
            Mnemonic::Cvttss2si => {
                let src_bits = match instr.op_kind(1) {
                    iced_x86::OpKind::Register => self.cpu.regs.get_xmm(instr.op_register(1))[0],
                    iced_x86::OpKind::Memory => self.mem.read_u32(self.cpu.eval_mem_addr(&instr)).unwrap_or(0) as u64,
                    _ => 0,
                };
                let val = (f32::from_bits(src_bits as u32) as i64) as u64;
                self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
            }
            Mnemonic::Addsd => {
                let v1 = f64::from_bits(self.cpu.regs.get_xmm(instr.op_register(0))[0]);
                let v2_bits = if instr.op_kind(1) == iced_x86::OpKind::Register { self.cpu.regs.get_xmm(instr.op_register(1))[0] } else { self.mem.read_u64(self.cpu.eval_mem_addr(&instr)).unwrap_or(0) };
                let res = (v1 + f64::from_bits(v2_bits)).to_bits();
                let mut xmm = self.cpu.regs.get_xmm(instr.op_register(0));
                xmm[0] = res;
                self.cpu.regs.set_xmm(instr.op_register(0), xmm);
            }
            Mnemonic::Subsd => {
                let v1 = f64::from_bits(self.cpu.regs.get_xmm(instr.op_register(0))[0]);
                let v2_bits = if instr.op_kind(1) == iced_x86::OpKind::Register { self.cpu.regs.get_xmm(instr.op_register(1))[0] } else { self.mem.read_u64(self.cpu.eval_mem_addr(&instr)).unwrap_or(0) };
                let res = (v1 - f64::from_bits(v2_bits)).to_bits();
                let mut xmm = self.cpu.regs.get_xmm(instr.op_register(0));
                xmm[0] = res;
                self.cpu.regs.set_xmm(instr.op_register(0), xmm);
            }
            Mnemonic::Mulsd => {
                let v1 = f64::from_bits(self.cpu.regs.get_xmm(instr.op_register(0))[0]);
                let v2_bits = if instr.op_kind(1) == iced_x86::OpKind::Register { self.cpu.regs.get_xmm(instr.op_register(1))[0] } else { self.mem.read_u64(self.cpu.eval_mem_addr(&instr)).unwrap_or(0) };
                let res = (v1 * f64::from_bits(v2_bits)).to_bits();
                let mut xmm = self.cpu.regs.get_xmm(instr.op_register(0));
                xmm[0] = res;
                self.cpu.regs.set_xmm(instr.op_register(0), xmm);
            }
            Mnemonic::Divsd => {
                let v1 = f64::from_bits(self.cpu.regs.get_xmm(instr.op_register(0))[0]);
                let v2_bits = if instr.op_kind(1) == iced_x86::OpKind::Register { self.cpu.regs.get_xmm(instr.op_register(1))[0] } else { self.mem.read_u64(self.cpu.eval_mem_addr(&instr)).unwrap_or(0) };
                let res = (v1 / f64::from_bits(v2_bits)).to_bits();
                let mut xmm = self.cpu.regs.get_xmm(instr.op_register(0));
                xmm[0] = res;
                self.cpu.regs.set_xmm(instr.op_register(0), xmm);
            }
            Mnemonic::Movsd | Mnemonic::Movss | Mnemonic::Movq | Mnemonic::Movd => {
                match (instr.op_kind(0), instr.op_kind(1)) {
                    (iced_x86::OpKind::Register, iced_x86::OpKind::Register) => {
                        if CpuRegisters::xmm_idx(instr.op_register(0)).is_some() {
                            if CpuRegisters::xmm_idx(instr.op_register(1)).is_some() {
                                let val = self.cpu.regs.get_xmm(instr.op_register(1));
                                self.cpu.regs.set_xmm(instr.op_register(0), val);
                            } else {
                                let val = self.cpu.regs.get_reg(instr.op_register(1));
                                self.cpu.regs.set_xmm(instr.op_register(0), [val, 0]);
                            }
                        } else {
                            let val = self.cpu.regs.get_xmm(instr.op_register(1))[0];
                            self.cpu.regs.set_reg(instr.op_register(0), val);
                        }
                    }
                    (iced_x86::OpKind::Register, iced_x86::OpKind::Memory) => {
                        let addr = self.cpu.eval_mem_addr(&instr);
                        let val = self.mem.read_u64(addr).unwrap_or(0);
                        if CpuRegisters::xmm_idx(instr.op_register(0)).is_some() {
                            self.cpu.regs.set_xmm(instr.op_register(0), [val, 0]);
                        } else {
                            self.cpu.regs.set_reg(instr.op_register(0), val);
                        }
                    }
                    (iced_x86::OpKind::Memory, iced_x86::OpKind::Register) => {
                        let addr = self.cpu.eval_mem_addr(&instr);
                        let val = if CpuRegisters::xmm_idx(instr.op_register(1)).is_some() {
                            self.cpu.regs.get_xmm(instr.op_register(1))[0]
                        } else {
                            self.cpu.regs.get_reg(instr.op_register(1))
                        };
                        self.mem.write_u64(addr, val);
                    }
                    _ => {}
                }
            }
            Mnemonic::Movaps | Mnemonic::Movups | Mnemonic::Movdqa | Mnemonic::Movdqu => {
                match (instr.op_kind(0), instr.op_kind(1)) {
                    (iced_x86::OpKind::Register, iced_x86::OpKind::Register) => {
                        let val = self.cpu.regs.get_xmm(instr.op_register(1));
                        self.cpu.regs.set_xmm(instr.op_register(0), val);
                    }
                    (iced_x86::OpKind::Register, iced_x86::OpKind::Memory) => {
                        let addr = self.cpu.eval_mem_addr(&instr);
                        let mut bytes = [0u8; 16];
                        self.mem.read_bytes(addr, &mut bytes);
                        let w0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                        let w1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                        self.cpu.regs.set_xmm(instr.op_register(0), [w0, w1]);
                    }
                    (iced_x86::OpKind::Memory, iced_x86::OpKind::Register) => {
                        let addr = self.cpu.eval_mem_addr(&instr);
                        let [w0, w1] = self.cpu.regs.get_xmm(instr.op_register(1));
                        self.mem.write_bytes(addr, &w0.to_le_bytes());
                        self.mem.write_bytes(addr + 8, &w1.to_le_bytes());
                    }
                    _ => {}
                }
            }
            Mnemonic::Nop => {}
            Mnemonic::Xchg => {
                let v0 = self.cpu.get_op_val(&instr, 0, &self.mem);
                let v1 = self.cpu.get_op_val(&instr, 1, &self.mem);
                self.cpu.set_op_val(&instr, 0, v1, &mut self.mem);
                self.cpu.set_op_val(&instr, 1, v0, &mut self.mem);
            }
            Mnemonic::Cmove => {
                if (self.cpu.regs.rflags & CpuRegisters::ZF) != 0 {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovne => {
                if (self.cpu.regs.rflags & CpuRegisters::ZF) == 0 {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovb => {
                if (self.cpu.regs.rflags & CpuRegisters::CF) != 0 {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovae => {
                if (self.cpu.regs.rflags & CpuRegisters::CF) == 0 {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovg => {
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if !zf && (sf == of) {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovge => {
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if sf == of {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovl => {
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if sf != of {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovle => {
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if zf || (sf != of) {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmova => {
                let cf = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                if !cf && !zf {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovbe => {
                let cf = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                if cf || zf {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovs => {
                if (self.cpu.regs.rflags & CpuRegisters::SF) != 0 {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Cmovns => {
                if (self.cpu.regs.rflags & CpuRegisters::SF) == 0 {
                    let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                    self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
                }
            }
            Mnemonic::Mov => {
                let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
            }
            Mnemonic::Movzx => {
                let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
            }
            Mnemonic::Movsx | Mnemonic::Movsxd => {
                let val = self.cpu.get_op_val(&instr, 1, &self.mem);
                let sign_extended = match instr.code() {
                    Code::Movsxd_r64_rm32 => (val as i32 as i64) as u64,
                    Code::Movsx_r32_rm8 | Code::Movsx_r64_rm8 => (val as i8 as i64) as u64,
                    Code::Movsx_r32_rm16 | Code::Movsx_r64_rm16 => (val as i16 as i64) as u64,
                    _ => (val as i32 as i64) as u64,
                };
                self.cpu.set_op_val(&instr, 0, sign_extended, &mut self.mem);
            }
            Mnemonic::Lea => {
                let addr = self.cpu.eval_mem_addr(&instr);
                self.cpu.set_op_val(&instr, 0, addr, &mut self.mem);
            }
            Mnemonic::Push => {
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                self.cpu.regs.rsp -= 8;
                self.mem.write_u64(self.cpu.regs.rsp, val);
            }
            Mnemonic::Pop => {
                let val = self.mem.read_u64(self.cpu.regs.rsp).unwrap_or(0);
                self.cpu.regs.rsp += 8;
                self.cpu.set_op_val(&instr, 0, val, &mut self.mem);
            }
            Mnemonic::Xor => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let res = dst ^ src;
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                self.update_logic_flags(res, size);
            }
            Mnemonic::And => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let res = dst & src;
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                self.update_logic_flags(res, size);
            }
            Mnemonic::Or => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let res = dst | src;
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                self.update_logic_flags(res, size);
            }
            Mnemonic::Add => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let res = self.eval_add_flags(dst, src, size);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Adc => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let carry_in = if (self.cpu.regs.rflags & CpuRegisters::CF) != 0 { 1u64 } else { 0u64 };
                let (res1, c1) = dst.overflowing_add(src);
                let (res, c2) = res1.overflowing_add(carry_in);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                let full_res = self.eval_add_flags(dst, src, size);
                if carry_in != 0 {
                    let _ = self.eval_add_flags(full_res, carry_in, size);
                }
                if c1 || c2 {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                }
            }
            Mnemonic::Sub => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let res = self.eval_sub_flags(dst, src, size);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Sbb => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let borrow_in = if (self.cpu.regs.rflags & CpuRegisters::CF) != 0 { 1u64 } else { 0u64 };
                let (res1, b1) = dst.overflowing_sub(src);
                let (res, b2) = res1.overflowing_sub(borrow_in);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                let full_res = self.eval_sub_flags(dst, src, size);
                if borrow_in != 0 {
                    let _ = self.eval_sub_flags(full_res, borrow_in, size);
                }
                if b1 || b2 {
                    self.cpu.regs.rflags |= CpuRegisters::CF;
                }
            }
            Mnemonic::Xadd => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                let res = self.eval_add_flags(dst, src, size);
                self.cpu.set_op_val(&instr, 1, dst, &mut self.mem);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Bswap => {
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                let res = val.swap_bytes();
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Rol => {
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let shift = (self.cpu.get_op_val(&instr, 1, &self.mem) & 0x3f) as u32;
                let res = dst.rotate_left(shift);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Ror => {
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let shift = (self.cpu.get_op_val(&instr, 1, &self.mem) & 0x3f) as u32;
                let res = dst.rotate_right(shift);
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
            }
            Mnemonic::Cmp => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                self.eval_sub_flags(dst, src, size);
            }
            Mnemonic::Test => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let dst = self.cpu.get_op_val(&instr, 0, &self.mem);
                let src = self.cpu.get_op_val(&instr, 1, &self.mem);
                self.update_logic_flags(dst & src, size);
            }
            Mnemonic::Inc => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                let (res, overflow, zf, sf) = match size {
                    1 => {
                        let v = val as u8;
                        let r = v.wrapping_add(1);
                        (r as u64, v == 0x7F, r == 0, (r & 0x80) != 0)
                    }
                    2 => {
                        let v = val as u16;
                        let r = v.wrapping_add(1);
                        (r as u64, v == 0x7FFF, r == 0, (r & 0x8000) != 0)
                    }
                    4 => {
                        let v = val as u32;
                        let r = v.wrapping_add(1);
                        (r as u64, v == 0x7FFFFFFF, r == 0, (r & 0x80000000) != 0)
                    }
                    _ => {
                        let r = val.wrapping_add(1);
                        (r, val == 0x7FFFFFFFFFFFFFFF, r == 0, (r as i64) < 0)
                    }
                };
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                if zf { self.cpu.regs.rflags |= CpuRegisters::ZF; } else { self.cpu.regs.rflags &= !CpuRegisters::ZF; }
                if sf { self.cpu.regs.rflags |= CpuRegisters::SF; } else { self.cpu.regs.rflags &= !CpuRegisters::SF; }
                if overflow { self.cpu.regs.rflags |= CpuRegisters::OF; } else { self.cpu.regs.rflags &= !CpuRegisters::OF; }
            }
            Mnemonic::Dec => {
                let size = self.cpu.get_op_size_bytes(&instr, 0);
                let val = self.cpu.get_op_val(&instr, 0, &self.mem);
                let (res, overflow, zf, sf) = match size {
                    1 => {
                        let v = val as u8;
                        let r = v.wrapping_sub(1);
                        (r as u64, v == 0x80, r == 0, (r & 0x80) != 0)
                    }
                    2 => {
                        let v = val as u16;
                        let r = v.wrapping_sub(1);
                        (r as u64, v == 0x8000, r == 0, (r & 0x8000) != 0)
                    }
                    4 => {
                        let v = val as u32;
                        let r = v.wrapping_sub(1);
                        (r as u64, v == 0x80000000, r == 0, (r & 0x80000000) != 0)
                    }
                    _ => {
                        let r = val.wrapping_sub(1);
                        (r, val == 0x8000000000000000, r == 0, (r as i64) < 0)
                    }
                };
                self.cpu.set_op_val(&instr, 0, res, &mut self.mem);
                if zf { self.cpu.regs.rflags |= CpuRegisters::ZF; } else { self.cpu.regs.rflags &= !CpuRegisters::ZF; }
                if sf { self.cpu.regs.rflags |= CpuRegisters::SF; } else { self.cpu.regs.rflags &= !CpuRegisters::SF; }
                if overflow { self.cpu.regs.rflags |= CpuRegisters::OF; } else { self.cpu.regs.rflags &= !CpuRegisters::OF; }
            }
            Mnemonic::Call => {
                let target = self.cpu.get_op_val(&instr, 0, &self.mem);
                self.cpu.regs.rsp -= 8;
                self.mem.write_u64(self.cpu.regs.rsp, next_rip);
                self.cpu.regs.rip = target;
            }
            Mnemonic::Ret => {
                let return_addr = self.mem.read_u64(self.cpu.regs.rsp).unwrap_or(0);
                self.cpu.regs.rsp += 8;
                if return_addr == 0 {
                    self.cpu.halted = true;
                } else {
                    self.cpu.regs.rip = return_addr;
                }
            }
            Mnemonic::Jmp => {
                let target = self.cpu.get_op_val(&instr, 0, &self.mem);
                self.cpu.regs.rip = target;
            }
            Mnemonic::Jnp => {
                if (self.cpu.regs.rflags & (1 << 2)) == 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jp => {
                if (self.cpu.regs.rflags & (1 << 2)) != 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Js => {
                if (self.cpu.regs.rflags & CpuRegisters::SF) != 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jns => {
                if (self.cpu.regs.rflags & CpuRegisters::SF) == 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jo => {
                if (self.cpu.regs.rflags & CpuRegisters::OF) != 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jno => {
                if (self.cpu.regs.rflags & CpuRegisters::OF) == 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Je => {
                if (self.cpu.regs.rflags & CpuRegisters::ZF) != 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jne => {
                if (self.cpu.regs.rflags & CpuRegisters::ZF) == 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jl => {
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if sf != of {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jle => {
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if zf || (sf != of) {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jg => {
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if !zf && (sf == of) {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jge => {
                let sf = (self.cpu.regs.rflags & CpuRegisters::SF) != 0;
                let of = (self.cpu.regs.rflags & CpuRegisters::OF) != 0;
                if sf == of {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jb => {
                if (self.cpu.regs.rflags & CpuRegisters::CF) != 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jbe => {
                let cf = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                if cf || zf {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Ja => {
                let cf = (self.cpu.regs.rflags & CpuRegisters::CF) != 0;
                let zf = (self.cpu.regs.rflags & CpuRegisters::ZF) != 0;
                if !cf && !zf {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Jae => {
                if (self.cpu.regs.rflags & CpuRegisters::CF) == 0 {
                    self.cpu.regs.rip = self.cpu.get_op_val(&instr, 0, &self.mem);
                }
            }
            Mnemonic::Syscall => {
                self.dispatch_syscall()?;
                if self.cpu.halted {
                    return Ok(false);
                }
            }
            Mnemonic::Cpuid => {
                let leaf = self.cpu.regs.rax as u32;
                let _sub_leaf = self.cpu.regs.rcx as u32;

                match leaf {
                    0 => {
                        // Max basic leaf & GenuineIntel
                        self.cpu.regs.rax = 0x16;
                        self.cpu.regs.rbx = 0x756e6547; // "Genu"
                        self.cpu.regs.rdx = 0x49656e69; // "ineI"
                        self.cpu.regs.rcx = 0x6c65746e; // "ntel"
                    }
                    1 => {
                        // Standard x86-64 CPU features: SSE, SSE2, SSE3, SSSE3, SSE4.1, SSE4.2, POPCNT (baseline SSE2 target)
                        self.cpu.regs.rax = 0x000806ea;
                        self.cpu.regs.rbx = 0x01080800;
                        self.cpu.regs.rcx = 0x01f83203;
                        self.cpu.regs.rdx = 0x078bfbff;
                    }
                    7 => {
                        self.cpu.regs.rax = 0;
                        self.cpu.regs.rbx = 0;
                        self.cpu.regs.rcx = 0;
                        self.cpu.regs.rdx = 0;
                    }
                    0x80000000 => {
                        self.cpu.regs.rax = 0x80000008;
                        self.cpu.regs.rbx = 0;
                        self.cpu.regs.rcx = 0;
                        self.cpu.regs.rdx = 0;
                    }
                    _ => {
                        self.cpu.regs.rax = 0;
                        self.cpu.regs.rbx = 0;
                        self.cpu.regs.rcx = 0;
                        self.cpu.regs.rdx = 0;
                    }
                }
            }
            Mnemonic::Xgetbv => {
                let ecx = self.cpu.regs.rcx as u32;
                if ecx == 0 {
                    // XCR0: bit 0 (x87), bit 1 (SSE), bit 2 (AVX) enabled
                    self.cpu.regs.rax = 7;
                    self.cpu.regs.rdx = 0;
                } else {
                    self.cpu.regs.rax = 0;
                    self.cpu.regs.rdx = 0;
                }
            }
            Mnemonic::Rdtsc => {
                // Deterministic logical clock reading
                let ticks = self.vkernel.virtual_time.0;
                self.cpu.regs.rax = (ticks & 0xffffffff) as u64;
                self.cpu.regs.rdx = ((ticks >> 32) & 0xffffffff) as u64;
            }
            _ => {
                // Unhandled instruction
                return Err(format!(
                    "Unsupported instruction {:?} at RIP {:#x}",
                    instr.mnemonic(),
                    rip
                ));
            }
        }

        Ok(!self.cpu.halted)
    }

    fn update_logic_flags(&mut self, res: u64, size: usize) {
        let (zf, sf) = match size {
            1 => ((res as u8) == 0, (res as u8 & 0x80) != 0),
            2 => ((res as u16) == 0, (res as u16 & 0x8000) != 0),
            4 => ((res as u32) == 0, (res as u32 & 0x80000000) != 0),
            _ => (res == 0, (res as i64) < 0),
        };
        if zf {
            self.cpu.regs.rflags |= CpuRegisters::ZF;
        } else {
            self.cpu.regs.rflags &= !CpuRegisters::ZF;
        }
        if sf {
            self.cpu.regs.rflags |= CpuRegisters::SF;
        } else {
            self.cpu.regs.rflags &= !CpuRegisters::SF;
        }
        self.cpu.regs.rflags &= !(CpuRegisters::CF | CpuRegisters::OF);
    }

    fn eval_sub_flags(&mut self, dst: u64, src: u64, size: usize) -> u64 {
        let (res, borrow, overflow, zf, sf) = match size {
            1 => {
                let d = dst as u8;
                let s = src as u8;
                let (r, b) = d.overflowing_sub(s);
                let o = (d as i8).overflowing_sub(s as i8).1;
                (r as u64, b, o, r == 0, (r & 0x80) != 0)
            }
            2 => {
                let d = dst as u16;
                let s = src as u16;
                let (r, b) = d.overflowing_sub(s);
                let o = (d as i16).overflowing_sub(s as i16).1;
                (r as u64, b, o, r == 0, (r & 0x8000) != 0)
            }
            4 => {
                let d = dst as u32;
                let s = src as u32;
                let (r, b) = d.overflowing_sub(s);
                let o = (d as i32).overflowing_sub(s as i32).1;
                (r as u64, b, o, r == 0, (r & 0x80000000) != 0)
            }
            _ => {
                let (r, b) = dst.overflowing_sub(src);
                let o = (dst as i64).overflowing_sub(src as i64).1;
                (r, b, o, r == 0, (r as i64) < 0)
            }
        };

        if zf { self.cpu.regs.rflags |= CpuRegisters::ZF; } else { self.cpu.regs.rflags &= !CpuRegisters::ZF; }
        if sf { self.cpu.regs.rflags |= CpuRegisters::SF; } else { self.cpu.regs.rflags &= !CpuRegisters::SF; }
        if borrow { self.cpu.regs.rflags |= CpuRegisters::CF; } else { self.cpu.regs.rflags &= !CpuRegisters::CF; }
        if overflow { self.cpu.regs.rflags |= CpuRegisters::OF; } else { self.cpu.regs.rflags &= !CpuRegisters::OF; }

        res
    }

    fn eval_add_flags(&mut self, dst: u64, src: u64, size: usize) -> u64 {
        let (res, carry, overflow, zf, sf) = match size {
            1 => {
                let d = dst as u8;
                let s = src as u8;
                let (r, c) = d.overflowing_add(s);
                let o = (d as i8).overflowing_add(s as i8).1;
                (r as u64, c, o, r == 0, (r & 0x80) != 0)
            }
            2 => {
                let d = dst as u16;
                let s = src as u16;
                let (r, c) = d.overflowing_add(s);
                let o = (d as i16).overflowing_add(s as i16).1;
                (r as u64, c, o, r == 0, (r & 0x8000) != 0)
            }
            4 => {
                let d = dst as u32;
                let s = src as u32;
                let (r, c) = d.overflowing_add(s);
                let o = (d as i32).overflowing_add(s as i32).1;
                (r as u64, c, o, r == 0, (r & 0x80000000) != 0)
            }
            _ => {
                let (r, c) = dst.overflowing_add(src);
                let o = (dst as i64).overflowing_add(src as i64).1;
                (r, c, o, r == 0, (r as i64) < 0)
            }
        };

        if zf { self.cpu.regs.rflags |= CpuRegisters::ZF; } else { self.cpu.regs.rflags &= !CpuRegisters::ZF; }
        if sf { self.cpu.regs.rflags |= CpuRegisters::SF; } else { self.cpu.regs.rflags &= !CpuRegisters::SF; }
        if carry { self.cpu.regs.rflags |= CpuRegisters::CF; } else { self.cpu.regs.rflags &= !CpuRegisters::CF; }
        if overflow { self.cpu.regs.rflags |= CpuRegisters::OF; } else { self.cpu.regs.rflags &= !CpuRegisters::OF; }

        res
    }

    /// Handles Linux syscalls trapping from the emulated process
    fn dispatch_syscall(&mut self) -> Result<(), String> {
        let nr = self.cpu.regs.rax as usize;
        let a0 = self.cpu.regs.rdi;
        let a1 = self.cpu.regs.rsi;
        let a2 = self.cpu.regs.rdx;
        let a3 = self.cpu.regs.r10;
        let a4 = self.cpu.regs.r8;
        let _a5 = self.cpu.regs.r9;

        if std::env::var("CRUCIBLE_DEBUG_SYSCALL").is_ok() {
            println!(
                "[SYSCALL] nr={}:{} a0={:#x} a1={:#x} a2={:#x} (step {})",
                nr,
                crucible_vkernel::syscall_name(nr),
                a0,
                a1,
                a2,
                self.cpu.instruction_count
            );
        }

        match nr {
            sys_nr::EXIT => {
                self.vkernel.exit_code = Some(a0 as i32);
                self.threads[self.current_thread_idx].halted = true;
                if !self.schedule_next_thread() {
                    self.cpu.halted = true;
                }
            }
            sys_nr::EXIT_GROUP => {
                self.vkernel.exit_code = Some(a0 as i32);
                for t in &mut self.threads {
                    t.halted = true;
                }
                self.cpu.halted = true;
                self.cpu.regs.rax = 0;
            }
            sys_nr::WRITE | sys_nr::SENDTO => {
                let fd = a0 as i32;
                let buf_addr = a1;
                let count = a2 as usize;
                let mut data = vec![0u8; count];
                self.mem.read_bytes(buf_addr, &mut data);

                let written = match self.vkernel.fds.get_mut(&fd) {
                    Some(FileDescriptor::StandardOutput(out)) => {
                        out.extend_from_slice(&data);
                        println!("[STDOUT] {}", String::from_utf8_lossy(&data));
                        count as u64
                    }
                    Some(FileDescriptor::StandardError(err)) => {
                        err.extend_from_slice(&data);
                        eprintln!("[STDERR] {}", String::from_utf8_lossy(&data));
                        count as u64
                    }
                    Some(FileDescriptor::Socket {
                        state: SocketState::Connected { conn_id, .. },
                        ..
                    }) => {
                        if let Some(conn) = self.vkernel.network.connections.get_mut(conn_id) {
                            conn.c2s_buffer.extend(data);
                            count as u64
                        } else {
                            (-9i64) as u64 // -EBADF
                        }
                    }
                    _ => (-9i64) as u64,
                };
                self.cpu.regs.rax = written;
            }
            sys_nr::READ | sys_nr::RECVFROM => {
                let fd = a0 as i32;
                let buf_addr = a1;
                let count = a2 as usize;

                let read_bytes = match self.vkernel.fds.get_mut(&fd) {
                    Some(FileDescriptor::Socket {
                        state: SocketState::Connected { conn_id, .. },
                        non_blocking,
                        ..
                    }) => {
                        let is_non_blocking = *non_blocking;
                        if let Some(conn) = self.vkernel.network.connections.get_mut(conn_id) {
                            if !conn.c2s_buffer.is_empty() {
                                let available = conn.c2s_buffer.len().min(count);
                                let drained: Vec<u8> = conn.c2s_buffer.drain(..available).collect();
                                self.mem.write_bytes(buf_addr, &drained);
                                available as u64
                            } else if conn.server_closed || conn.client_closed {
                                0
                            } else if is_non_blocking {
                                (-11i64) as u64 // -EAGAIN
                            } else {
                                0
                            }
                        } else {
                            (-9i64) as u64
                        }
                    }
                    _ => 0,
                };
                self.cpu.regs.rax = read_bytes;
            }
            sys_nr::SOCKET => {
                let domain = a0 as i32;
                let sock_type = a1 as i32;
                let protocol = a2 as i32;
                let fd = self.vkernel.alloc_fd(FileDescriptor::Socket {
                    domain,
                    sock_type,
                    protocol,
                    state: SocketState::Unbound,
                    non_blocking: false,
                    reuse_addr: false,
                    tcp_nodelay: false,
                });
                self.cpu.regs.rax = fd as u64;
            }
            sys_nr::BIND => {
                let fd = a0 as i32;
                let addr_ptr = a1;
                // Read sockaddr_in: { sin_family: u16, sin_port: u16, sin_addr: u32 }
                let port = self.mem.read_u16(addr_ptr + 2).unwrap_or(0).to_be();
                let ip = self.mem.read_u32(addr_ptr + 4).unwrap_or(0).to_be();
                let saddr = SocketAddrV4::new(ip, port);

                if let Some(FileDescriptor::Socket { state, .. }) = self.vkernel.fds.get_mut(&fd) {
                    *state = SocketState::Bound(saddr);
                    self.vkernel.network.bindings.insert(saddr, fd);
                    self.cpu.regs.rax = 0;
                } else {
                    self.cpu.regs.rax = u64::MAX;
                }
            }
            sys_nr::LISTEN => {
                let fd = a0 as i32;
                let backlog = a1 as usize;
                if let Some(FileDescriptor::Socket { state, .. }) = self.vkernel.fds.get_mut(&fd) {
                    if let SocketState::Bound(addr) = *state {
                        *state = SocketState::Listening {
                            addr,
                            backlog,
                            incoming_queue: std::collections::VecDeque::new(),
                        };
                        self.cpu.regs.rax = 0;
                    } else {
                        self.cpu.regs.rax = u64::MAX;
                    }
                } else {
                    self.cpu.regs.rax = u64::MAX;
                }
            }
            sys_nr::CONNECT => {
                let client_fd = a0 as i32;
                let addr_ptr = a1;
                let port = self.mem.read_u16(addr_ptr + 2).unwrap_or(0).to_be();
                let ip = self.mem.read_u32(addr_ptr + 4).unwrap_or(0).to_be();
                let remote_addr = SocketAddrV4::new(ip, port);

                if let Some(&listener_fd) = self.vkernel.network.bindings.get(&remote_addr) {
                    let conn_id = self.vkernel.network.allocate_connection();
                    let local_addr = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 45000);

                    // Add to listener queue
                    if let Some(FileDescriptor::Socket {
                        state: SocketState::Listening { incoming_queue, .. },
                        ..
                    }) = self.vkernel.fds.get_mut(&listener_fd)
                    {
                        incoming_queue.push_back(conn_id);
                    }

                    // Update client state
                    if let Some(FileDescriptor::Socket { state, .. }) =
                        self.vkernel.fds.get_mut(&client_fd)
                    {
                        *state = SocketState::Connected {
                            local: local_addr,
                            remote: remote_addr,
                            conn_id,
                        };
                        self.cpu.regs.rax = 0;
                    } else {
                        self.cpu.regs.rax = u64::MAX;
                    }
                } else {
                    self.cpu.regs.rax = u64::MAX; // Connection refused
                }
            }
            sys_nr::ACCEPT | sys_nr::ACCEPT4 => {
                let listener_fd = a0 as i32;
                let flags = if nr == sys_nr::ACCEPT4 { a3 as i32 } else { 0 };
                let mut conn_to_accept = None;

                if let Some(FileDescriptor::Socket {
                    state:
                        SocketState::Listening {
                            addr,
                            incoming_queue,
                            ..
                        },
                    ..
                }) = self.vkernel.fds.get_mut(&listener_fd)
                {
                    if let Some(conn_id) = incoming_queue.pop_front() {
                        conn_to_accept = Some((*addr, conn_id));
                    }
                }

                if let Some((local, conn_id)) = conn_to_accept {
                    let non_blocking = (flags & 0x800) != 0;
                    let client_socket_fd = self.vkernel.alloc_fd(FileDescriptor::Socket {
                        domain: 2,
                        sock_type: 1,
                        protocol: 0,
                        state: SocketState::Connected {
                            local,
                            remote: SocketAddrV4::new(SocketAddrV4::LOCALHOST, 45000),
                            conn_id,
                        },
                        non_blocking,
                        reuse_addr: false,
                        tcp_nodelay: false,
                    });
                    self.cpu.regs.rax = client_socket_fd as u64;
                } else {
                    self.cpu.regs.rax = (-11i64) as u64; // -EAGAIN / would block
                }
            }
            sys_nr::GETSOCKNAME => {
                let fd = a0 as i32;
                let addr_ptr = a1;
                let addrlen_ptr = a2;

                if let Some(FileDescriptor::Socket { state, .. }) = self.vkernel.fds.get(&fd) {
                    let saddr = match state {
                        SocketState::Bound(a) => *a,
                        SocketState::Listening { addr, .. } => *addr,
                        SocketState::Connected { local, .. } => *local,
                        _ => SocketAddrV4::new(SocketAddrV4::LOCALHOST, 0),
                    };
                    self.mem.write_u16(addr_ptr, 2); // AF_INET
                    self.mem.write_u16(addr_ptr + 2, saddr.port.to_be());
                    self.mem.write_u32(addr_ptr + 4, saddr.ip.to_be());
                    self.mem.write_u64(addr_ptr + 8, 0);
                    if addrlen_ptr != 0 {
                        self.mem.write_u32(addrlen_ptr, 16);
                    }
                    self.cpu.regs.rax = 0;
                } else {
                    self.cpu.regs.rax = (-9i64) as u64; // -EBADF
                }
            }
            sys_nr::GETPEERNAME => {
                let fd = a0 as i32;
                let addr_ptr = a1;
                let addrlen_ptr = a2;

                if let Some(FileDescriptor::Socket { state, .. }) = self.vkernel.fds.get(&fd) {
                    if let SocketState::Connected { remote, .. } = state {
                        self.mem.write_u16(addr_ptr, 2); // AF_INET
                        self.mem.write_u16(addr_ptr + 2, remote.port.to_be());
                        self.mem.write_u32(addr_ptr + 4, remote.ip.to_be());
                        self.mem.write_u64(addr_ptr + 8, 0);
                        if addrlen_ptr != 0 {
                            self.mem.write_u32(addrlen_ptr, 16);
                        }
                        self.cpu.regs.rax = 0;
                    } else {
                        self.cpu.regs.rax = (-107i64) as u64; // -ENOTCONN
                    }
                } else {
                    self.cpu.regs.rax = (-9i64) as u64;
                }
            }
            sys_nr::SETSOCKOPT => {
                let fd = a0 as i32;
                let level = a1 as i32;
                let optname = a2 as i32;
                let optval = a3;

                if let Some(FileDescriptor::Socket { reuse_addr, tcp_nodelay, .. }) =
                    self.vkernel.fds.get_mut(&fd)
                {
                    if level == 1 && optname == 2 {
                        let val = self.mem.read_u32(optval).unwrap_or(0);
                        *reuse_addr = val != 0;
                    }
                    if level == 6 && optname == 1 {
                        let val = self.mem.read_u32(optval).unwrap_or(0);
                        *tcp_nodelay = val != 0;
                    }
                    self.cpu.regs.rax = 0;
                } else {
                    self.cpu.regs.rax = (-9i64) as u64;
                }
            }
            sys_nr::GETSOCKOPT => {
                let fd = a0 as i32;
                let level = a1 as i32;
                let optname = a2 as i32;
                let optval = a3;
                let optlen_ptr = a4;

                if let Some(FileDescriptor::Socket { reuse_addr, tcp_nodelay, .. }) =
                    self.vkernel.fds.get(&fd)
                {
                    let mut val = 0u32;
                    if level == 1 && optname == 2 {
                        val = if *reuse_addr { 1 } else { 0 };
                    }
                    if level == 6 && optname == 1 {
                        val = if *tcp_nodelay { 1 } else { 0 };
                    }
                    if optval != 0 {
                        self.mem.write_u32(optval, val);
                    }
                    if optlen_ptr != 0 {
                        self.mem.write_u32(optlen_ptr, 4);
                    }
                    self.cpu.regs.rax = 0;
                } else {
                    self.cpu.regs.rax = (-9i64) as u64;
                }
            }
            sys_nr::EPOLL_CREATE | sys_nr::EPOLL_CREATE1 => {
                let fd = self.vkernel.alloc_epoll();
                self.cpu.regs.rax = fd as u64;
            }
            sys_nr::EPOLL_CTL => {
                let epfd = a0 as i32;
                let op = a1 as i32;
                let target_fd = a2 as i32;
                let event_ptr = a3;

                let instance_id_opt = match self.vkernel.fds.get(&epfd) {
                    Some(FileDescriptor::Epoll { instance_id }) => Some(*instance_id),
                    _ => None,
                };

                if let Some(instance_id) = instance_id_opt {
                    if let Some(instance) = self.vkernel.epoll_instances.get_mut(&instance_id) {
                        match op {
                            epoll_const::EPOLL_CTL_ADD | epoll_const::EPOLL_CTL_MOD => {
                                let events = self.mem.read_u32(event_ptr).unwrap_or(0);
                                let data = self.mem.read_u64(event_ptr + 4).unwrap_or(0);
                                instance.watched.insert(
                                    target_fd,
                                    EpollWatchEntry { events, data },
                                );
                                self.cpu.regs.rax = 0;
                            }
                            epoll_const::EPOLL_CTL_DEL => {
                                instance.watched.remove(&target_fd);
                                self.cpu.regs.rax = 0;
                            }
                            _ => {
                                self.cpu.regs.rax = (-22i64) as u64; // -EINVAL
                            }
                        }
                    } else {
                        self.cpu.regs.rax = (-9i64) as u64; // -EBADF
                    }
                } else {
                    self.cpu.regs.rax = (-9i64) as u64; // -EBADF
                }
            }
            sys_nr::EPOLL_WAIT | sys_nr::EPOLL_PWAIT => {
                let epfd = a0 as i32;
                let events_ptr = a1;
                let maxevents = a2 as usize;
                let timeout = a3 as i32;

                let instance_id_opt = match self.vkernel.fds.get(&epfd) {
                    Some(FileDescriptor::Epoll { instance_id }) => Some(*instance_id),
                    _ => None,
                };

                if let Some(instance_id) = instance_id_opt {
                    let ready_events = if let Some(instance) = self.vkernel.epoll_instances.get(&instance_id) {
                        instance.poll_ready(&self.vkernel.fds, &self.vkernel.network)
                    } else {
                        Vec::new()
                    };

                    if ready_events.is_empty() {
                        if timeout > 0 {
                            self.vkernel.virtual_time.0 += (timeout as u64).min(10) * 1_000_000;
                        }
                        self.cpu.regs.rax = 0;
                    } else {
                        let to_write = ready_events.len().min(maxevents);
                        for (i, ev) in ready_events.iter().take(to_write).enumerate() {
                            let item_ptr = events_ptr + (i as u64) * 12;
                            self.mem.write_u32(item_ptr, ev.events);
                            self.mem.write_u64(item_ptr + 4, ev.data);
                        }
                        self.cpu.regs.rax = to_write as u64;
                    }
                } else {
                    self.cpu.regs.rax = (-9i64) as u64;
                }
            }
            sys_nr::CLOSE => {
                let fd = a0 as i32;
                if let Some(fd_obj) = self.vkernel.fds.remove(&fd) {
                    match fd_obj {
                        FileDescriptor::Socket {
                            state: SocketState::Connected { conn_id, .. },
                            ..
                        } => {
                            if let Some(conn) = self.vkernel.network.connections.get_mut(&conn_id) {
                                conn.server_closed = true;
                            }
                        }
                        FileDescriptor::Epoll { instance_id } => {
                            self.vkernel.epoll_instances.remove(&instance_id);
                        }
                        _ => {}
                    }
                }
                self.cpu.regs.rax = 0;
            }
            sys_nr::POLL => {
                let fds_ptr = a0;
                let nfds = a1 as usize;
                for i in 0..nfds {
                    let pfd = fds_ptr + (i as u64) * 8;
                    let events = self.mem.read_u16(pfd + 4).unwrap_or(0);
                    self.mem.write_u16(pfd + 6, events);
                }
                self.cpu.regs.rax = a1;
            }
            sys_nr::BRK => {
                let target = a0;
                if target == 0 {
                    self.cpu.regs.rax = self.vkernel.brk_current;
                } else {
                    self.vkernel.brk_current = target;
                    self.cpu.regs.rax = target;
                }
            }
            sys_nr::MMAP => {
                let hint = a0;
                let len = a1;
                let addr = if hint != 0 {
                    self.vkernel.mmap_next = self.vkernel.mmap_next.max(hint + ((len + 0xfff) & !0xfff));
                    hint
                } else {
                    let addr = self.vkernel.mmap_next;
                    self.vkernel.mmap_next += (len + 0xfff) & !0xfff;
                    addr
                };
                self.cpu.regs.rax = addr;
            }
            sys_nr::MUNMAP => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::SCHED_YIELD => {
                let tid = self.threads[self.current_thread_idx].id;
                self.scheduler.notify_sync_event(tid, None, SyncEvent::Yield);
                self.cpu.regs.rax = 0;
                self.schedule_next_thread();
            }
            sys_nr::MADVISE => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::SIGALTSTACK => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::TGKILL => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::FCNTL => {
                let fd = a0 as i32;
                let cmd = a1 as i32;
                let arg = a2;

                match cmd {
                    3 => {
                        // F_GETFL
                        let flags = if let Some(FileDescriptor::Socket { non_blocking, .. }) =
                            self.vkernel.fds.get(&fd)
                        {
                            if *non_blocking { 0x800 } else { 0 }
                        } else {
                            0
                        };
                        self.cpu.regs.rax = flags as u64;
                    }
                    4 => {
                        // F_SETFL
                        if let Some(FileDescriptor::Socket { non_blocking, .. }) =
                            self.vkernel.fds.get_mut(&fd)
                        {
                            *non_blocking = (arg & 0x800) != 0;
                        }
                        self.cpu.regs.rax = 0;
                    }
                    _ => {
                        self.cpu.regs.rax = 0;
                    }
                }
            }
            sys_nr::NANOSLEEP => {
                self.vkernel.virtual_time.0 += 1_000_000; // +1ms logical time
                self.cpu.regs.rax = 0;
            }
            sys_nr::PIPE2 => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::OPENAT | sys_nr::NEWFSTATAT => {
                // Return -ENOENT (-2) for non-virtualized system files
                self.cpu.regs.rax = (-2i64) as u64;
            }
            sys_nr::PRCTL => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::ARCH_PRCTL => {
                let code = a0;
                let addr = a1;
                if code == 0x1002 {
                    // ARCH_SET_FS
                    self.cpu.regs.fs_base = addr;
                    self.cpu.regs.rax = 0;
                } else if code == 0x1003 {
                    // ARCH_GET_FS
                    self.mem.write_u64(addr, self.cpu.regs.fs_base);
                    self.cpu.regs.rax = 0;
                } else {
                    self.cpu.regs.rax = u64::MAX;
                }
            }
            sys_nr::MPROTECT => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::RT_SIGPROCMASK | sys_nr::RT_SIGACTION => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::FUTEX => {
                let cmd = a1 & 0x7f;
                match cmd {
                    0 | 9 => {
                        // FUTEX_WAIT / FUTEX_WAIT_BITSET
                        let val = a2 as u32;
                        let mem_val = self.mem.read_u32(a0).unwrap_or(0);
                        if mem_val != val {
                            self.cpu.regs.rax = (-11i64) as u64; // -EAGAIN
                        } else {
                            let tid = self.threads[self.current_thread_idx].id;
                            self.vkernel.futexes.wait(a0, tid);
                            self.threads[self.current_thread_idx].is_blocked = true;
                            self.scheduler.mark_blocked(tid);
                            self.scheduler.notify_sync_event(tid, None, SyncEvent::FutexWait);
                            self.cpu.regs.rax = 0;
                            self.threads[self.current_thread_idx].regs = self.cpu.regs;
                            if !self.schedule_next_thread() {
                                self.cpu.halted = true;
                            }
                        }
                    }
                    1 | 10 => {
                        // FUTEX_WAKE / FUTEX_WAKE_BITSET
                        let count = a2 as usize;
                        let source_tid = self.threads[self.current_thread_idx].id;
                        let woken = self.vkernel.futexes.wake(a0, count);
                        for tid in &woken {
                            if let Some(t) = self.threads.iter_mut().find(|t| t.id == *tid) {
                                t.is_blocked = false;
                                self.scheduler.mark_unblocked(*tid);
                                self.scheduler.notify_sync_event(
                                    source_tid,
                                    Some(*tid),
                                    SyncEvent::FutexWake { count: count as u32 },
                                );
                            }
                        }
                        self.cpu.regs.rax = woken.len() as u64;
                    }
                    _ => {
                        self.cpu.regs.rax = 0;
                    }
                }
            }
            sys_nr::RSEQ => {
                // Return -ENOSYS (-38) so runtime falls back to standard atomic ops
                self.cpu.regs.rax = (-38i64) as u64;
            }
            sys_nr::SCHED_GETAFFINITY => {
                // Return single core mask
                if a2 >= 8 {
                    self.mem.write_u64(a1, 1);
                    self.cpu.regs.rax = 8;
                } else {
                    self.cpu.regs.rax = 0;
                }
            }
            sys_nr::READLINK | sys_nr::READLINKAT => {
                // -ENOENT (-2)
                self.cpu.regs.rax = (-2i64) as u64;
            }
            sys_nr::PRLIMIT64 => {
                self.cpu.regs.rax = 0;
            }
            sys_nr::SET_TID_ADDRESS => {
                self.vkernel.clear_child_tid = a0;
                self.cpu.regs.rax = self.threads[self.current_thread_idx].id.0 as u64;
            }
            sys_nr::GETPID => {
                self.cpu.regs.rax = 1000;
            }
            sys_nr::GETTID => {
                self.cpu.regs.rax = self.threads[self.current_thread_idx].id.0 as u64;
            }
            sys_nr::CLONE => {
                let flags = a0;
                let child_stack = a1;
                let child_tid = ThreadId(1000 + self.threads.len() as u32);

                let mut child_regs = self.cpu.regs;
                child_regs.rax = 0;
                child_regs.rsp = child_stack;
                child_regs.rip = self.cpu.regs.rip;
                if (flags & 0x80000) != 0 {
                    child_regs.fs_base = self.cpu.regs.r8;
                }

                self.threads.push(EmulatedThreadState {
                    id: child_tid,
                    regs: child_regs,
                    is_blocked: false,
                    halted: false,
                });
                self.scheduler.register_thread(child_tid);

                self.cpu.regs.rax = child_tid.0 as u64;
            }
            sys_nr::CLOCK_GETTIME => {
                let timespec_ptr = a1;
                let nanos = self.vkernel.virtual_time.0;
                let secs = nanos / 1_000_000_000;
                let nsec = nanos % 1_000_000_000;
                self.mem.write_u64(timespec_ptr, secs);
                self.mem.write_u64(timespec_ptr + 8, nsec);
                self.cpu.regs.rax = 0;
            }
            sys_nr::GETRANDOM => {
                let buf_addr = a0;
                let len = a1 as usize;
                for i in 0..len {
                    let rand_byte = (self.vkernel.deterministic_random_u64() & 0xff) as u8;
                    self.mem.write_u8(buf_addr + i as u64, rand_byte);
                }
                self.cpu.regs.rax = len as u64;
            }
            _ => {
                return Err(format!(
                    "Unimplemented Linux syscall {} ({}) at RIP {:#x}",
                    nr,
                    crucible_vkernel::syscall_name(nr),
                    self.cpu.regs.rip
                ));
            }
        }

        Ok(())
    }
}
