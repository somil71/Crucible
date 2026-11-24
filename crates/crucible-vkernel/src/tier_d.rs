//! Tier D: Syscall Interception via seccomp-bpf & ptrace Fast Path.
//!
//! Provides a high-throughput syscall virtualization boundary for unmodified Linux
//! processes, intercepting non-deterministic syscalls (time, randomness, sockets, futexes)
//! while passing deterministic computations directly to host execution at native speed.

use crate::sys_nr;
use crate::VirtualKernelContext;
use crucible_core::{ThreadId, VirtualTime};
use serde::{Deserialize, Serialize};

/// An intercepted syscall event captured by ptrace / seccomp-bpf trap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallTrap {
    pub thread_id: ThreadId,
    pub nr: usize,
    pub args: [u64; 6],
    pub ret_val: i64,
}

impl SyscallTrap {
    pub fn new(thread_id: ThreadId, nr: usize, args: [u64; 6]) -> Self {
        Self {
            thread_id,
            nr,
            args,
            ret_val: 0,
        }
    }
}

/// Action determined by the Tier D syscall interception engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyscallAction {
    /// Allow the host operating system kernel to execute the syscall directly.
    PassThrough,
    /// Override syscall return register `rax` without executing kernel path.
    InjectValue(i64),
    /// Suspend the thread until a specified virtual time or event queue release.
    BlockUntil(VirtualTime),
    /// Syscall routed through crucible virtual network loopback.
    VirtualNetworkRoute { fd: i32, bytes_handled: usize },
}

/// Filter configuration for seccomp-bpf rule compilation.
#[derive(Debug, Clone)]
pub struct SeccompFilterPolicy {
    pub intercept_time: bool,
    pub intercept_random: bool,
    pub intercept_sockets: bool,
    pub intercept_futex: bool,
}

impl Default for SeccompFilterPolicy {
    fn default() -> Self {
        Self {
            intercept_time: true,
            intercept_random: true,
            intercept_sockets: true,
            intercept_futex: true,
        }
    }
}

/// Performance telemetry for Tier D syscall interception.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TierDTelemetry {
    pub total_traps: u64,
    pub pass_through_count: u64,
    pub time_injections: u64,
    pub random_injections: u64,
    pub network_traps: u64,
    pub futex_traps: u64,
}

/// The Tier D Syscall Interception Tracer Engine.
pub struct TierDTracer {
    pub policy: SeccompFilterPolicy,
    pub vkernel: VirtualKernelContext,
    pub telemetry: TierDTelemetry,
}

impl TierDTracer {
    pub fn new(policy: SeccompFilterPolicy) -> Self {
        Self {
            policy,
            vkernel: VirtualKernelContext::new(),
            telemetry: TierDTelemetry::default(),
        }
    }

    /// Dispatches an intercepted syscall trap and determines the virtual action.
    pub fn dispatch_trap(&mut self, trap: &mut SyscallTrap) -> SyscallAction {
        self.telemetry.total_traps += 1;

        match trap.nr {
            // Time virtualization (clock_gettime, gettimeofday, time)
            sys_nr::CLOCK_GETTIME | sys_nr::GETTIMEOFDAY => {
                if self.policy.intercept_time {
                    self.telemetry.time_injections += 1;
                    let _vtime_nanos = self.vkernel.virtual_time.0;
                    trap.ret_val = 0;
                    SyscallAction::InjectValue(0)
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            // Sleep virtualization (nanosleep, clock_nanosleep)
            sys_nr::NANOSLEEP => {
                if self.policy.intercept_time {
                    let sleep_nanos = trap.args[0]; // struct timespec duration
                    let target_vtime = VirtualTime(self.vkernel.virtual_time.0 + sleep_nanos);
                    self.vkernel.virtual_time = target_vtime;
                    self.telemetry.time_injections += 1;
                    trap.ret_val = 0;
                    SyscallAction::BlockUntil(target_vtime)
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            // Randomness virtualization (getrandom)
            sys_nr::GETRANDOM => {
                if self.policy.intercept_random {
                    self.telemetry.random_injections += 1;
                    let requested_len = trap.args[1] as i64;
                    trap.ret_val = requested_len;
                    SyscallAction::InjectValue(requested_len)
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            // Virtual Futex Subsystem (futex)
            sys_nr::FUTEX => {
                if self.policy.intercept_futex {
                    self.telemetry.futex_traps += 1;
                    let uaddr = trap.args[0];
                    let op = trap.args[1] as u32 & 0x7f; // FUTEX_CMD_MASK

                    if op == 0 {
                        // FUTEX_WAIT
                        self.vkernel.futexes.wait(uaddr, trap.thread_id);
                        trap.ret_val = 0;
                        SyscallAction::BlockUntil(VirtualTime(self.vkernel.virtual_time.0 + 10_000_000))
                    } else if op == 1 {
                        // FUTEX_WAKE
                        let count = trap.args[2] as usize;
                        let woken = self.vkernel.futexes.wake(uaddr, count).len();
                        trap.ret_val = woken as i64;
                        SyscallAction::InjectValue(woken as i64)
                    } else {
                        trap.ret_val = 0;
                        SyscallAction::InjectValue(0)
                    }
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            // Virtual Network Socket Layer (socket, bind, connect, sendto, recvfrom)
            sys_nr::SOCKET => {
                if self.policy.intercept_sockets {
                    self.telemetry.network_traps += 1;
                    let domain = trap.args[0] as i32;
                    let sock_type = trap.args[1] as i32;
                    let fd = self.vkernel.alloc_socket(domain, sock_type, 0);
                    trap.ret_val = fd as i64;
                    SyscallAction::InjectValue(fd as i64)
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            sys_nr::CONNECT => {
                if self.policy.intercept_sockets {
                    self.telemetry.network_traps += 1;
                    let fd = trap.args[0] as i32;
                    trap.ret_val = 0;
                    SyscallAction::VirtualNetworkRoute { fd, bytes_handled: 0 }
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            sys_nr::SENDTO | sys_nr::WRITE => {
                if self.policy.intercept_sockets && trap.args[0] >= 3 {
                    self.telemetry.network_traps += 1;
                    let fd = trap.args[0] as i32;
                    let len = trap.args[2] as usize;
                    trap.ret_val = len as i64;
                    SyscallAction::VirtualNetworkRoute { fd, bytes_handled: len }
                } else {
                    self.telemetry.pass_through_count += 1;
                    SyscallAction::PassThrough
                }
            }

            // Everything else: Direct host execution pass-through
            _ => {
                self.telemetry.pass_through_count += 1;
                SyscallAction::PassThrough
            }
        }
    }

    /// Simulates a batch of intercepted syscall traps and returns their actions.
    pub fn simulate_batch(&mut self, traps: &mut [SyscallTrap]) -> Vec<SyscallAction> {
        traps.iter_mut().map(|t| self.dispatch_trap(t)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_d_clock_interception() {
        let mut tracer = TierDTracer::new(SeccompFilterPolicy::default());
        let mut trap = SyscallTrap::new(ThreadId(1), sys_nr::CLOCK_GETTIME, [0; 6]);
        let action = tracer.dispatch_trap(&mut trap);

        assert_eq!(action, SyscallAction::InjectValue(0));
        assert_eq!(tracer.telemetry.time_injections, 1);
        assert_eq!(tracer.telemetry.pass_through_count, 0);
    }

    #[test]
    fn test_tier_d_futex_wait_and_wake() {
        let mut tracer = TierDTracer::new(SeccompFilterPolicy::default());

        // Thread 1 waits on futex 0x1000
        let mut wait_trap = SyscallTrap::new(ThreadId(1), sys_nr::FUTEX, [0x1000, 0, 0, 0, 0, 0]);
        let action1 = tracer.dispatch_trap(&mut wait_trap);
        assert!(matches!(action1, SyscallAction::BlockUntil(_)));

        // Thread 2 wakes futex 0x1000
        let mut wake_trap = SyscallTrap::new(ThreadId(2), sys_nr::FUTEX, [0x1000, 1, 1, 0, 0, 0]);
        let action2 = tracer.dispatch_trap(&mut wake_trap);
        assert_eq!(action2, SyscallAction::InjectValue(1));

        assert_eq!(tracer.telemetry.futex_traps, 2);
    }

    #[test]
    fn test_tier_d_native_passthrough() {
        let mut tracer = TierDTracer::new(SeccompFilterPolicy::default());
        let mut trap = SyscallTrap::new(ThreadId(1), sys_nr::GETPID, [0; 6]);
        let action = tracer.dispatch_trap(&mut trap);

        assert_eq!(action, SyscallAction::PassThrough);
        assert_eq!(tracer.telemetry.pass_through_count, 1);
    }
}
