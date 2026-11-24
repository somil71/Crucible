//! Tier D Syscall Interception Integration Test Suite.
//!
//! Validates seccomp-bpf trap handling, virtual time injection, futex scheduling,
//! and native execution pass-through for unmodified Linux binaries.

use crucible_core::{ThreadId, VirtualTime};
use crucible_vkernel::sys_nr;
use crucible_vkernel::tier_d::{SeccompFilterPolicy, SyscallAction, SyscallTrap, TierDTracer};

#[test]
fn test_tier_d_comprehensive_syscall_census() {
    let mut tracer = TierDTracer::new(SeccompFilterPolicy::default());

    // 1. Clock Interception
    let mut clock_trap = SyscallTrap::new(ThreadId(1), sys_nr::CLOCK_GETTIME, [0, 0x7ffffff0, 0, 0, 0, 0]);
    assert_eq!(tracer.dispatch_trap(&mut clock_trap), SyscallAction::InjectValue(0));

    // 2. Sleep Interception (Virtual time advances immediately by 50ms)
    let sleep_nanos = 50_000_000;
    let mut sleep_trap = SyscallTrap::new(ThreadId(1), sys_nr::NANOSLEEP, [sleep_nanos, 0, 0, 0, 0, 0]);
    let action = tracer.dispatch_trap(&mut sleep_trap);
    match action {
        SyscallAction::BlockUntil(target_vtime) => {
            assert!(target_vtime > VirtualTime::ZERO);
        }
        other => panic!("Expected BlockUntil, got {other:?}"),
    }

    // 3. PRNG Interception (getrandom returns requested size deterministically)
    let mut rand_trap = SyscallTrap::new(ThreadId(1), sys_nr::GETRANDOM, [0x2000, 32, 0, 0, 0, 0]);
    assert_eq!(tracer.dispatch_trap(&mut rand_trap), SyscallAction::InjectValue(32));

    // 4. Virtual Socket Creation
    let mut sock_trap = SyscallTrap::new(ThreadId(1), sys_nr::SOCKET, [2, 1, 0, 0, 0, 0]); // AF_INET, SOCK_STREAM
    let sock_action = tracer.dispatch_trap(&mut sock_trap);
    match sock_action {
        SyscallAction::InjectValue(fd) => assert!(fd >= 3, "Allocated FD must be >= 3"),
        other => panic!("Expected InjectValue(fd), got {other:?}"),
    }

    // 5. Native Pass-Through (e.g. getpid, brk)
    let mut pid_trap = SyscallTrap::new(ThreadId(1), sys_nr::GETPID, [0; 6]);
    assert_eq!(tracer.dispatch_trap(&mut pid_trap), SyscallAction::PassThrough);

    // Verify Telemetry counters
    assert_eq!(tracer.telemetry.total_traps, 5);
    assert_eq!(tracer.telemetry.time_injections, 2);
    assert_eq!(tracer.telemetry.random_injections, 1);
    assert_eq!(tracer.telemetry.network_traps, 1);
    assert_eq!(tracer.telemetry.pass_through_count, 1);
}

#[test]
fn test_tier_d_policy_toggling() {
    // Disable time virtualization: time syscalls must pass through to kernel
    let policy = SeccompFilterPolicy {
        intercept_time: false,
        intercept_random: true,
        intercept_sockets: true,
        intercept_futex: true,
    };
    let mut tracer = TierDTracer::new(policy);

    let mut clock_trap = SyscallTrap::new(ThreadId(1), sys_nr::CLOCK_GETTIME, [0; 6]);
    assert_eq!(tracer.dispatch_trap(&mut clock_trap), SyscallAction::PassThrough);
    assert_eq!(tracer.telemetry.pass_through_count, 1);
    assert_eq!(tracer.telemetry.time_injections, 0);
}
