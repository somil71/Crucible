//! Crucible Virtual Kernel - User-space implementation of Linux syscalls and deterministic resources.

use crucible_core::{ThreadId, VirtualTime};
use std::collections::{HashMap, VecDeque};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VKernelError {
    #[error("Unsupported syscall {nr} ({name}) with args {args:?}")]
    UnsupportedSyscall {
        nr: usize,
        name: &'static str,
        args: [u64; 6],
    },
    #[error("Bad file descriptor {0}")]
    BadFd(i32),
    #[error("Memory access fault at {addr:#x} (len {len})")]
    MemoryFault { addr: u64, len: usize },
    #[error("Address already in use: {0}:{1}")]
    AddressInUse(u32, u16),
    #[error("Connection refused: {0}:{1}")]
    ConnectionRefused(u32, u16),
}

/// Linux x86-64 syscall numbers.
pub mod sys_nr {
    pub const READ: usize = 0;
    pub const WRITE: usize = 1;
    pub const CLOSE: usize = 3;
    pub const POLL: usize = 7;
    pub const MMAP: usize = 9;
    pub const MPROTECT: usize = 10;
    pub const MUNMAP: usize = 11;
    pub const BRK: usize = 12;
    pub const RT_SIGACTION: usize = 13;
    pub const RT_SIGPROCMASK: usize = 14;
    pub const IOCTL: usize = 16;
    pub const SCHED_YIELD: usize = 24;
    pub const MADVISE: usize = 28;
    pub const NANOSLEEP: usize = 35;
    pub const GETPID: usize = 39;
    pub const SOCKET: usize = 41;
    pub const CONNECT: usize = 42;
    pub const ACCEPT: usize = 43;
    pub const SENDTO: usize = 44;
    pub const RECVFROM: usize = 45;
    pub const BIND: usize = 49;
    pub const LISTEN: usize = 50;
    pub const GETSOCKNAME: usize = 51;
    pub const GETPEERNAME: usize = 52;
    pub const SETSOCKOPT: usize = 54;
    pub const GETSOCKOPT: usize = 55;
    pub const CLONE: usize = 56;
    pub const EXIT: usize = 60;
    pub const FCNTL: usize = 72;
    pub const READLINK: usize = 89;
    pub const SIGALTSTACK: usize = 131;
    pub const PRCTL: usize = 157;
    pub const ARCH_PRCTL: usize = 158;
    pub const GETTID: usize = 186;
    pub const FUTEX: usize = 202;
    pub const SCHED_GETAFFINITY: usize = 204;
    pub const EPOLL_CREATE: usize = 213;
    pub const SET_TID_ADDRESS: usize = 218;
    pub const CLOCK_GETTIME: usize = 228;
    pub const EXIT_GROUP: usize = 231;
    pub const EPOLL_WAIT: usize = 232;
    pub const EPOLL_CTL: usize = 233;
    pub const TGKILL: usize = 234;
    pub const OPENAT: usize = 257;
    pub const NEWFSTATAT: usize = 262;
    pub const READLINKAT: usize = 267;
    pub const EPOLL_PWAIT: usize = 281;
    pub const ACCEPT4: usize = 288;
    pub const EPOLL_CREATE1: usize = 291;
    pub const PIPE2: usize = 293;
    pub const PRLIMIT64: usize = 302;
    pub const GETRANDOM: usize = 318;
    pub const RSEQ: usize = 334;
}

/// Syscall Classification Category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallCategory {
    Pure,
    Stateful,
    Nondeterministic,
    Unsupported,
}

pub fn classify_syscall(nr: usize) -> SyscallCategory {
    match nr {
        sys_nr::READ | sys_nr::WRITE | sys_nr::CLOSE | sys_nr::SOCKET
        | sys_nr::BIND | sys_nr::LISTEN | sys_nr::ACCEPT | sys_nr::ACCEPT4 | sys_nr::CONNECT
        | sys_nr::SETSOCKOPT | sys_nr::GETSOCKOPT | sys_nr::GETSOCKNAME | sys_nr::GETPEERNAME
        | sys_nr::SENDTO | sys_nr::RECVFROM
        | sys_nr::FUTEX | sys_nr::EPOLL_CREATE | sys_nr::EPOLL_CREATE1
        | sys_nr::EPOLL_CTL | sys_nr::EPOLL_WAIT | sys_nr::EPOLL_PWAIT
        | sys_nr::CLONE | sys_nr::EXIT
        | sys_nr::EXIT_GROUP | sys_nr::MMAP | sys_nr::MUNMAP | sys_nr::BRK | sys_nr::MPROTECT => {
            SyscallCategory::Stateful
        }
        sys_nr::CLOCK_GETTIME | sys_nr::GETRANDOM | sys_nr::GETPID | sys_nr::NANOSLEEP => {
            SyscallCategory::Nondeterministic
        }
        _ => SyscallCategory::Unsupported,
    }
}

pub fn syscall_name(nr: usize) -> &'static str {
    match nr {
        sys_nr::READ => "sys_read",
        sys_nr::WRITE => "sys_write",
        sys_nr::CLOSE => "sys_close",
        sys_nr::POLL => "sys_poll",
        sys_nr::MMAP => "sys_mmap",
        sys_nr::MPROTECT => "sys_mprotect",
        sys_nr::MUNMAP => "sys_munmap",
        sys_nr::BRK => "sys_brk",
        sys_nr::RT_SIGACTION => "sys_rt_sigaction",
        sys_nr::RT_SIGPROCMASK => "sys_rt_sigprocmask",
        sys_nr::IOCTL => "sys_ioctl",
        sys_nr::SCHED_YIELD => "sys_sched_yield",
        sys_nr::MADVISE => "sys_madvise",
        sys_nr::NANOSLEEP => "sys_nanosleep",
        sys_nr::GETPID => "sys_getpid",
        sys_nr::SOCKET => "sys_socket",
        sys_nr::CONNECT => "sys_connect",
        sys_nr::ACCEPT => "sys_accept",
        sys_nr::ACCEPT4 => "sys_accept4",
        sys_nr::SENDTO => "sys_sendto",
        sys_nr::RECVFROM => "sys_recvfrom",
        sys_nr::BIND => "sys_bind",
        sys_nr::LISTEN => "sys_listen",
        sys_nr::GETSOCKNAME => "sys_getsockname",
        sys_nr::GETPEERNAME => "sys_getpeername",
        sys_nr::SETSOCKOPT => "sys_setsockopt",
        sys_nr::GETSOCKOPT => "sys_getsockopt",
        sys_nr::CLONE => "sys_clone",
        sys_nr::EXIT => "sys_exit",
        sys_nr::FCNTL => "sys_fcntl",
        sys_nr::READLINK => "sys_readlink",
        sys_nr::SIGALTSTACK => "sys_sigaltstack",
        sys_nr::PRCTL => "sys_prctl",
        sys_nr::ARCH_PRCTL => "sys_arch_prctl",
        sys_nr::GETTID => "sys_gettid",
        sys_nr::FUTEX => "sys_futex",
        sys_nr::SCHED_GETAFFINITY => "sys_sched_getaffinity",
        sys_nr::EPOLL_CREATE => "sys_epoll_create",
        sys_nr::SET_TID_ADDRESS => "sys_set_tid_address",
        sys_nr::CLOCK_GETTIME => "sys_clock_gettime",
        sys_nr::EXIT_GROUP => "sys_exit_group",
        sys_nr::EPOLL_WAIT => "sys_epoll_wait",
        sys_nr::EPOLL_CTL => "sys_epoll_ctl",
        sys_nr::TGKILL => "sys_tgkill",
        sys_nr::EPOLL_PWAIT => "sys_epoll_pwait",
        sys_nr::EPOLL_CREATE1 => "sys_epoll_create1",
        sys_nr::PIPE2 => "sys_pipe2",
        sys_nr::OPENAT => "sys_openat",
        sys_nr::NEWFSTATAT => "sys_newfstatat",
        sys_nr::READLINKAT => "sys_readlinkat",
        sys_nr::PRLIMIT64 => "sys_prlimit64",
        sys_nr::GETRANDOM => "sys_getrandom",
        sys_nr::RSEQ => "sys_rseq",
        _ => "unknown",
    }
}

/// Representation of a socket endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketAddrV4 {
    pub ip: u32,
    pub port: u16,
}

impl SocketAddrV4 {
    pub const LOCALHOST: u32 = 0x7f000001; // 127.0.0.1
    pub fn new(ip: u32, port: u16) -> Self {
        Self { ip, port }
    }
}

/// State of a virtual socket.
#[derive(Debug)]
pub enum SocketState {
    Unbound,
    Bound(SocketAddrV4),
    Listening {
        addr: SocketAddrV4,
        backlog: usize,
        incoming_queue: VecDeque<u64>,
    },
    Connected {
        local: SocketAddrV4,
        remote: SocketAddrV4,
        conn_id: u64,
    },
    Closed,
}

/// Bi-directional in-memory byte pipe connecting two sockets.
#[derive(Default, Debug)]
pub struct VirtualConnection {
    pub c2s_buffer: VecDeque<u8>,
    pub s2c_buffer: VecDeque<u8>,
    pub client_closed: bool,
    pub server_closed: bool,
}

/// Epoll event flags matching Linux sys/epoll.h
pub mod epoll_const {
    pub const EPOLLIN: u32 = 0x0001;
    pub const EPOLLPRI: u32 = 0x0002;
    pub const EPOLLOUT: u32 = 0x0004;
    pub const EPOLLERR: u32 = 0x0008;
    pub const EPOLLHUP: u32 = 0x0010;
    pub const EPOLLRDHUP: u32 = 0x2000;
    pub const EPOLLET: u32 = 1 << 31;
    pub const EPOLLONESHOT: u32 = 1 << 30;

    pub const EPOLL_CTL_ADD: i32 = 1;
    pub const EPOLL_CTL_DEL: i32 = 2;
    pub const EPOLL_CTL_MOD: i32 = 3;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

#[derive(Debug, Clone)]
pub struct EpollWatchEntry {
    pub events: u32,
    pub data: u64,
}

#[derive(Default, Debug, Clone)]
pub struct EpollInstance {
    pub watched: HashMap<i32, EpollWatchEntry>,
}

impl EpollInstance {
    pub fn poll_ready(&self, fds: &HashMap<i32, FileDescriptor>, network: &VirtualNetwork) -> Vec<EpollEvent> {
        let mut ready = Vec::new();
        let mut sorted_watched: Vec<_> = self.watched.iter().collect();
        sorted_watched.sort_by_key(|(&fd, _)| fd);

        for (&fd, entry) in sorted_watched {
            let mut current_mask = 0u32;
            match fds.get(&fd) {
                Some(FileDescriptor::Socket { state, .. }) => {
                    match state {
                        SocketState::Listening { incoming_queue, .. } => {
                            if !incoming_queue.is_empty() {
                                current_mask |= epoll_const::EPOLLIN;
                            }
                        }
                        SocketState::Connected { conn_id, .. } => {
                            if let Some(conn) = network.connections.get(conn_id) {
                                if !conn.c2s_buffer.is_empty() {
                                    current_mask |= epoll_const::EPOLLIN;
                                }
                                if !conn.server_closed && !conn.client_closed {
                                    current_mask |= epoll_const::EPOLLOUT;
                                }
                                if conn.server_closed || conn.client_closed {
                                    current_mask |= epoll_const::EPOLLHUP | epoll_const::EPOLLIN;
                                }
                            } else {
                                current_mask |= epoll_const::EPOLLERR;
                            }
                        }
                        SocketState::Closed => {
                            current_mask |= epoll_const::EPOLLHUP;
                        }
                        _ => {}
                    }
                }
                Some(FileDescriptor::StandardInput) => {
                    current_mask |= epoll_const::EPOLLIN;
                }
                Some(FileDescriptor::StandardOutput(_)) | Some(FileDescriptor::StandardError(_)) => {
                    current_mask |= epoll_const::EPOLLOUT;
                }
                _ => {}
            }

            let matched = current_mask & (entry.events | epoll_const::EPOLLERR | epoll_const::EPOLLHUP);
            if matched != 0 {
                ready.push(EpollEvent {
                    events: matched,
                    data: entry.data,
                });
            }
        }
        ready
    }
}

/// Virtual File Descriptor in a process table.
#[derive(Debug)]
pub enum FileDescriptor {
    StandardInput,
    StandardOutput(Vec<u8>),
    StandardError(Vec<u8>),
    Socket {
        domain: i32,
        sock_type: i32,
        protocol: i32,
        state: SocketState,
        non_blocking: bool,
        reuse_addr: bool,
        tcp_nodelay: bool,
    },
    Epoll {
        instance_id: u64,
    },
}

/// Deterministic Virtual Network layer.
#[derive(Default)]
pub struct VirtualNetwork {
    pub bindings: HashMap<SocketAddrV4, i32>,
    pub connections: HashMap<u64, VirtualConnection>,
    next_conn_id: u64,
}

impl VirtualNetwork {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            connections: HashMap::new(),
            next_conn_id: 1,
        }
    }

    pub fn allocate_connection(&mut self) -> u64 {
        let id = self.next_conn_id;
        self.next_conn_id += 1;
        self.connections.insert(id, VirtualConnection::default());
        id
    }
}

/// Virtual Futex registry for deterministic thread synchronization.
#[derive(Default)]
pub struct FutexRegistry {
    waiters: HashMap<u64, VecDeque<ThreadId>>,
}

impl FutexRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn wait(&mut self, addr: u64, thread: ThreadId) {
        self.waiters.entry(addr).or_default().push_back(thread);
    }

    pub fn wake(&mut self, addr: u64, count: usize) -> Vec<ThreadId> {
        let mut awakened = Vec::new();
        if let Some(queue) = self.waiters.get_mut(&addr) {
            for _ in 0..count {
                if let Some(t) = queue.pop_front() {
                    awakened.push(t);
                } else {
                    break;
                }
            }
        }
        awakened
    }
}

/// Virtual Process Kernel Context.
pub struct VirtualKernelContext {
    pub virtual_time: VirtualTime,
    pub futexes: FutexRegistry,
    pub network: VirtualNetwork,
    pub fds: HashMap<i32, FileDescriptor>,
    pub epoll_instances: HashMap<u64, EpollInstance>,
    pub next_epoll_id: u64,
    pub next_fd: i32,
    pub brk_current: u64,
    pub mmap_next: u64,
    pub clear_child_tid: u64,
    pub exit_code: Option<i32>,
    pub pseudo_rand_state: u64,
}

impl Default for VirtualKernelContext {
    fn default() -> Self {
        let mut fds = HashMap::new();
        fds.insert(0, FileDescriptor::StandardInput);
        fds.insert(1, FileDescriptor::StandardOutput(Vec::new()));
        fds.insert(2, FileDescriptor::StandardError(Vec::new()));

        Self {
            virtual_time: VirtualTime(1_700_000_000_000_000_000), // Deterministic non-zero epoch (1.7e9 seconds)
            futexes: FutexRegistry::new(),
            network: VirtualNetwork::new(),
            fds,
            epoll_instances: HashMap::new(),
            next_epoll_id: 1,
            next_fd: 3,
            brk_current: 0x600000,
            mmap_next: 0x700000000000,
            clear_child_tid: 0,
            exit_code: None,
            pseudo_rand_state: 0x123456789abcdef0,
        }
    }
}

impl VirtualKernelContext {
    pub fn alloc_fd(&mut self, desc: FileDescriptor) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.fds.insert(fd, desc);
        fd
    }

    pub fn alloc_epoll(&mut self) -> i32 {
        let epoll_id = self.next_epoll_id;
        self.next_epoll_id += 1;
        self.epoll_instances.insert(epoll_id, EpollInstance::default());
        self.alloc_fd(FileDescriptor::Epoll { instance_id: epoll_id })
    }

    pub fn deterministic_random_u64(&mut self) -> u64 {
        let mut x = self.pseudo_rand_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.pseudo_rand_state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
}
