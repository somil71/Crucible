use crucible_emu::cpu::CpuRegisters;
use crucible_emu::interp::Emulator;
use crucible_emu::memory::VirtualMemory;
use iced_x86::Register;

// ==========================================
// 1. CPU Register File & Sub-register Aliasing (20 tests)
// ==========================================

#[test]
fn test_reg_rax_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RAX, 0x1122334455667788);
    assert_eq!(regs.get_reg(Register::RAX), 0x1122334455667788);
    assert_eq!(regs.get_reg(Register::EAX), 0x55667788);
    assert_eq!(regs.get_reg(Register::AX), 0x7788);
    assert_eq!(regs.get_reg(Register::AL), 0x88);
}

#[test]
fn test_reg_eax_write_clears_upper32() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RAX, 0xFFFFFFFFFFFFFFFF);
    regs.set_reg(Register::EAX, 0x12345678);
    // In x86-64, 32-bit register writes zero-extend into the 64-bit register
    assert_eq!(regs.get_reg(Register::RAX), 0x12345678);
}

#[test]
fn test_reg_rbx_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RBX, 0xAABBCCDDEEFF0011);
    assert_eq!(regs.get_reg(Register::RBX), 0xAABBCCDDEEFF0011);
    assert_eq!(regs.get_reg(Register::EBX), 0xEEFF0011);
    assert_eq!(regs.get_reg(Register::BX), 0x0011);
    assert_eq!(regs.get_reg(Register::BL), 0x11);
}

#[test]
fn test_reg_rcx_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RCX, 0x0102030405060708);
    assert_eq!(regs.get_reg(Register::RCX), 0x0102030405060708);
    assert_eq!(regs.get_reg(Register::ECX), 0x05060708);
    assert_eq!(regs.get_reg(Register::CX), 0x0708);
    assert_eq!(regs.get_reg(Register::CL), 0x08);
}

#[test]
fn test_reg_rdx_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RDX, 0x1020304050607080);
    assert_eq!(regs.get_reg(Register::RDX), 0x1020304050607080);
    assert_eq!(regs.get_reg(Register::EDX), 0x50607080);
    assert_eq!(regs.get_reg(Register::DX), 0x7080);
    assert_eq!(regs.get_reg(Register::DL), 0x80);
}

#[test]
fn test_reg_rsi_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RSI, 0x9988776655443322);
    assert_eq!(regs.get_reg(Register::RSI), 0x9988776655443322);
    assert_eq!(regs.get_reg(Register::ESI), 0x55443322);
    assert_eq!(regs.get_reg(Register::SI), 0x3322);
    assert_eq!(regs.get_reg(Register::SIL), 0x22);
}

#[test]
fn test_reg_rdi_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RDI, 0xFEDCBA9876543210);
    assert_eq!(regs.get_reg(Register::RDI), 0xFEDCBA9876543210);
    assert_eq!(regs.get_reg(Register::EDI), 0x76543210);
    assert_eq!(regs.get_reg(Register::DI), 0x3210);
    assert_eq!(regs.get_reg(Register::DIL), 0x10);
}

#[test]
fn test_reg_rbp_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RBP, 0x1212121234343434);
    assert_eq!(regs.get_reg(Register::RBP), 0x1212121234343434);
    assert_eq!(regs.get_reg(Register::EBP), 0x34343434);
    assert_eq!(regs.get_reg(Register::BP), 0x3434);
    assert_eq!(regs.get_reg(Register::BPL), 0x34);
}

#[test]
fn test_reg_rsp_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RSP, 0x7ffffffde000);
    assert_eq!(regs.get_reg(Register::RSP), 0x7ffffffde000);
    assert_eq!(regs.get_reg(Register::ESP), 0x7ffffffde000u64 & 0xFFFFFFFF);
}

#[test]
fn test_reg_r8_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R8, 0x1111222233334444);
    assert_eq!(regs.get_reg(Register::R8), 0x1111222233334444);
    assert_eq!(regs.get_reg(Register::R8D), 0x33334444);
    assert_eq!(regs.get_reg(Register::R8W), 0x4444);
    assert_eq!(regs.get_reg(Register::R8L), 0x44);
}

#[test]
fn test_reg_r9_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R9, 0x5555666677778888);
    assert_eq!(regs.get_reg(Register::R9), 0x5555666677778888);
    assert_eq!(regs.get_reg(Register::R9D), 0x77778888);
    assert_eq!(regs.get_reg(Register::R9W), 0x8888);
    assert_eq!(regs.get_reg(Register::R9L), 0x88);
}

#[test]
fn test_reg_r10_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R10, 0x9999AAAABBBBCCCC);
    assert_eq!(regs.get_reg(Register::R10), 0x9999AAAABBBBCCCC);
    assert_eq!(regs.get_reg(Register::R10D), 0xBBBBCCCC);
    assert_eq!(regs.get_reg(Register::R10W), 0xCCCC);
    assert_eq!(regs.get_reg(Register::R10L), 0xCC);
}

#[test]
fn test_reg_r11_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R11, 0xDDDDEEEEFFFF0000);
    assert_eq!(regs.get_reg(Register::R11), 0xDDDDEEEEFFFF0000);
    assert_eq!(regs.get_reg(Register::R11D), 0xFFFF0000);
}

#[test]
fn test_reg_r12_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R12, 0x0123456789ABCDEF);
    assert_eq!(regs.get_reg(Register::R12), 0x0123456789ABCDEF);
    assert_eq!(regs.get_reg(Register::R12D), 0x89ABCDEF);
}

#[test]
fn test_reg_r13_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R13, 0xFEDCBA9876543210);
    assert_eq!(regs.get_reg(Register::R13), 0xFEDCBA9876543210);
    assert_eq!(regs.get_reg(Register::R13D), 0x76543210);
}

#[test]
fn test_reg_r14_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R14, 0x4242424242424242);
    assert_eq!(regs.get_reg(Register::R14), 0x4242424242424242);
    assert_eq!(regs.get_reg(Register::R14D), 0x42424242);
}

#[test]
fn test_reg_r15_aliases() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::R15, 0x8484848484848484);
    assert_eq!(regs.get_reg(Register::R15), 0x8484848484848484);
    assert_eq!(regs.get_reg(Register::R15D), 0x84848484);
}

#[test]
fn test_reg_rip_read_write() {
    let mut regs = CpuRegisters::default();
    regs.set_reg(Register::RIP, 0x401000);
    assert_eq!(regs.get_reg(Register::RIP), 0x401000);
}

#[test]
fn test_reg_fs_base() {
    let mut regs = CpuRegisters::default();
    regs.fs_base = 0x70001000;
    assert_eq!(regs.fs_base, 0x70001000);
}

#[test]
fn test_reg_rflags_bits() {
    let mut regs = CpuRegisters::default();
    regs.rflags |= CpuRegisters::ZF | CpuRegisters::CF;
    assert_ne!(regs.rflags & CpuRegisters::ZF, 0);
    assert_ne!(regs.rflags & CpuRegisters::CF, 0);
    assert_eq!(regs.rflags & CpuRegisters::SF, 0);
}

// ==========================================
// 2. VirtualMemory Bounds & Accessors (15 tests)
// ==========================================

#[test]
fn test_mem_read_write_u8() {
    let mut mem = VirtualMemory::new();
    mem.write_u8(0x1000, 0xAB);
    assert_eq!(mem.read_u8(0x1000), Some(0xAB));
}

#[test]
fn test_mem_unwritten_returns_none() {
    let mem = VirtualMemory::new();
    assert_eq!(mem.read_u8(0x99999), None);
}

#[test]
fn test_mem_read_write_u16_le() {
    let mut mem = VirtualMemory::new();
    mem.write_u16(0x2000, 0x1234);
    assert_eq!(mem.read_u16(0x2000), Some(0x1234));
    assert_eq!(mem.read_u8(0x2000), Some(0x34)); // Little endian
    assert_eq!(mem.read_u8(0x2001), Some(0x12));
}

#[test]
fn test_mem_read_write_u32_le() {
    let mut mem = VirtualMemory::new();
    mem.write_u32(0x3000, 0xDEADBEEF);
    assert_eq!(mem.read_u32(0x3000), Some(0xDEADBEEF));
    assert_eq!(mem.read_u8(0x3000), Some(0xEF));
}

#[test]
fn test_mem_read_write_u64_le() {
    let mut mem = VirtualMemory::new();
    mem.write_u64(0x4000, 0x0123456789ABCDEF);
    assert_eq!(mem.read_u64(0x4000), Some(0x0123456789ABCDEF));
    assert_eq!(mem.read_u8(0x4000), Some(0xEF));
}

#[test]
fn test_mem_cross_page_write_and_read() {
    let mut mem = VirtualMemory::new();
    let addr = 4094; // Page boundary is at 4096
    mem.write_u64(addr, 0xAABBCCDDEEFF0011);
    assert_eq!(mem.read_u64(addr), Some(0xAABBCCDDEEFF0011));
}

#[test]
fn test_mem_read_cstring_valid() {
    let mut mem = VirtualMemory::new();
    mem.write_bytes(0x5000, b"crucible_string\0");
    let s = mem.read_cstring(0x5000, 100).unwrap();
    assert_eq!(s, b"crucible_string");
}

#[test]
fn test_mem_read_cstring_unallocated() {
    let mem = VirtualMemory::new();
    assert_eq!(mem.read_cstring(0x99999, 100), None);
}

#[test]
fn test_mem_write_bytes_slice() {
    let mut mem = VirtualMemory::new();
    let data = b"Testing 1 2 3";
    mem.write_bytes(0x6000, data);
    let mut buf = [0u8; 13];
    assert!(mem.read_bytes(0x6000, &mut buf));
    assert_eq!(&buf, data);
}

#[test]
fn test_mem_page_isolation() {
    let mut mem = VirtualMemory::new();
    mem.write_u8(0x1000, 1);
    mem.write_u8(0x2000, 2);
    assert_eq!(mem.read_u8(0x1000), Some(1));
    assert_eq!(mem.read_u8(0x2000), Some(2));
}

#[test]
fn test_mem_overwrite() {
    let mut mem = VirtualMemory::new();
    mem.write_u32(0x1000, 100);
    mem.write_u32(0x1000, 200);
    assert_eq!(mem.read_u32(0x1000), Some(200));
}

#[test]
fn test_mem_high_addresses() {
    let mut mem = VirtualMemory::new();
    let high_addr = 0x7ffffffde000u64;
    mem.write_u64(high_addr, 0x1234);
    assert_eq!(mem.read_u64(high_addr), Some(0x1234));
}

#[test]
fn test_mem_partial_unallocated_bytes_fails() {
    let mem = VirtualMemory::new();
    let mut buf = [0u8; 4];
    // Page 0x9000 is not allocated yet
    assert!(!mem.read_bytes(0x9000, &mut buf));
}

#[test]
fn test_mem_clone() {
    let mut mem1 = VirtualMemory::new();
    mem1.write_u64(0x100, 42);
    let mem2 = mem1.clone();
    assert_eq!(mem2.read_u64(0x100), Some(42));
}

#[test]
fn test_mem_default() {
    let mem: VirtualMemory = Default::default();
    assert_eq!(mem.read_u8(0), None);
}

// ==========================================
// 3. Instruction Stepper Execution (15 tests)
// ==========================================

#[test]
fn test_interp_nop() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    // Opcode for NOP: 90
    emu.mem.write_u8(0x1000, 0x90);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1001);
    assert_eq!(emu.cpu.instruction_count, 1);
}

#[test]
fn test_interp_mov_reg_imm() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    // mov eax, 42 -> b8 2a 00 00 00
    emu.mem.write_bytes(0x1000, &[0xb8, 0x2a, 0x00, 0x00, 0x00]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 42);
}

#[test]
fn test_interp_xor_same_reg_zeroes() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 0xFFFFFFFF;
    // xor eax, eax -> 31 c0
    emu.mem.write_bytes(0x1000, &[0x31, 0xc0]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 0);
    assert_ne!(emu.cpu.regs.rflags & CpuRegisters::ZF, 0);
}

#[test]
fn test_interp_add_reg_imm() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 10;
    // add eax, 5 -> 83 c0 05
    emu.mem.write_bytes(0x1000, &[0x83, 0xc0, 0x05]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 15);
}

#[test]
fn test_interp_sub_sets_zero_flag() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 5;
    // sub eax, 5 -> 83 e8 05
    emu.mem.write_bytes(0x1000, &[0x83, 0xe8, 0x05]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 0);
    assert_ne!(emu.cpu.regs.rflags & CpuRegisters::ZF, 0);
}

#[test]
fn test_interp_cmp_updates_flags_without_modifying_reg() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 100;
    // cmp eax, 100 -> 3d 64 00 00 00
    emu.mem.write_bytes(0x1000, &[0x3d, 0x64, 0x00, 0x00, 0x00]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 100); // Unchanged
    assert_ne!(emu.cpu.regs.rflags & CpuRegisters::ZF, 0);
}

#[test]
fn test_interp_inc_reg() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 41;
    // inc eax -> ff c0
    emu.mem.write_bytes(0x1000, &[0xff, 0xc0]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 42);
}

#[test]
fn test_interp_dec_reg() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 43;
    // dec eax -> ff c8
    emu.mem.write_bytes(0x1000, &[0xff, 0xc8]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 42);
}

#[test]
fn test_interp_push_and_pop() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 0x1234567890ABCDEF;
    // push rax -> 50
    emu.mem.write_u8(0x1000, 0x50);
    // pop rbx -> 5b
    emu.mem.write_u8(0x1001, 0x5b);

    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rsp, 0x7ffffffde000 - 8);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rsp, 0x7ffffffde000);
    assert_eq!(emu.cpu.regs.rbx, 0x1234567890ABCDEF);
}

#[test]
fn test_interp_jmp_forward() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    // jmp +5 (to 0x1007): eb 05
    emu.mem.write_bytes(0x1000, &[0xeb, 0x05]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1007);
}

#[test]
fn test_interp_je_taken_when_zf_set() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rflags |= CpuRegisters::ZF;
    // je +4 (to 0x1006): 74 04
    emu.mem.write_bytes(0x1000, &[0x74, 0x04]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1006);
}

#[test]
fn test_interp_je_not_taken_when_zf_clear() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rflags &= !CpuRegisters::ZF;
    // je +4: 74 04
    emu.mem.write_bytes(0x1000, &[0x74, 0x04]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1002); // Next sequential instruction
}

#[test]
fn test_interp_cpuid_intercept() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    // cpuid -> 0f a2
    emu.mem.write_bytes(0x1000, &[0x0f, 0xa2]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rbx, 0x756e6547); // "Genu"
}

#[test]
fn test_interp_rdtsc_intercept() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.vkernel.virtual_time = crucible_core::VirtualTime(1_000_000_000);
    // rdtsc -> 0f 31
    emu.mem.write_bytes(0x1000, &[0x0f, 0x31]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 1_000_000_010);
}

#[test]
fn test_interp_syscall_exit_halts() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = crucible_vkernel::sys_nr::EXIT as u64;
    emu.cpu.regs.rdi = 42;
    // syscall -> 0f 05
    emu.mem.write_bytes(0x1000, &[0x0f, 0x05]);
    let active = emu.step().unwrap();
    assert!(!active); // Halted
    assert_eq!(emu.vkernel.exit_code, Some(42));
}

// ==========================================
// 4. Advanced Conditionals & Edge Cases (10 tests)
// ==========================================

#[test]
fn test_interp_call_and_ret() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    // call 0x1006 -> e8 01 00 00 00
    emu.mem.write_bytes(0x1000, &[0xe8, 0x01, 0x00, 0x00, 0x00]);
    // hlt at 0x1005: f4
    emu.mem.write_u8(0x1005, 0xf4);
    // ret at 0x1006: c3
    emu.mem.write_u8(0x1006, 0xc3);

    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1006);
    assert_eq!(emu.cpu.regs.rsp, 0x7ffffffde000 - 8);

    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1005);
    assert_eq!(emu.cpu.regs.rsp, 0x7ffffffde000);
}

#[test]
fn test_interp_jne_taken() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rflags &= !CpuRegisters::ZF;
    // jne +4 (to 0x1006): 75 04
    emu.mem.write_bytes(0x1000, &[0x75, 0x04]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rip, 0x1006);
}

#[test]
fn test_interp_cdqe_sign_extend() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 0x80000000; // Negative i32
    // cdqe -> 48 98
    emu.mem.write_bytes(0x1000, &[0x48, 0x98]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 0xFFFFFFFF80000000);
}

#[test]
fn test_interp_cqo_negative() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 0x8000000000000000;
    // cqo -> 48 99
    emu.mem.write_bytes(0x1000, &[0x48, 0x99]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rdx, u64::MAX);
}

#[test]
fn test_interp_cqo_positive() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 0x7000000000000000;
    // cqo -> 48 99
    emu.mem.write_bytes(0x1000, &[0x48, 0x99]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rdx, 0);
}

#[test]
fn test_interp_shl() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 1;
    // shl rax, 4 -> 48 c1 e0 04
    emu.mem.write_bytes(0x1000, &[0x48, 0xc1, 0xe0, 0x04]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 16);
}

#[test]
fn test_interp_shr() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 64;
    // shr rax, 3 -> 48 c1 e8 03
    emu.mem.write_bytes(0x1000, &[0x48, 0xc1, 0xe8, 0x03]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, 8);
}

#[test]
fn test_interp_neg() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 5;
    // neg rax -> 48 f7 d8
    emu.mem.write_bytes(0x1000, &[0x48, 0xf7, 0xd8]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax as i64, -5);
}

#[test]
fn test_interp_not() {
    let mut emu = Emulator::new(0x1000, 0x7ffffffde000);
    emu.cpu.regs.rax = 0;
    // not rax -> 48 f7 d0
    emu.mem.write_bytes(0x1000, &[0x48, 0xf7, 0xd0]);
    assert!(emu.step().unwrap());
    assert_eq!(emu.cpu.regs.rax, u64::MAX);
}

#[test]
fn test_interp_rip_zero_halts() {
    let mut emu = Emulator::new(0, 0x7ffffffde000);
    assert_eq!(emu.step(), Ok(false));
    assert!(emu.cpu.halted);
}
