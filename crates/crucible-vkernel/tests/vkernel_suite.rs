use crucible_core::ThreadId;
use crucible_vkernel::{
    classify_syscall, sys_nr, syscall_name, FileDescriptor, FutexRegistry, SocketAddrV4,
    SocketState, SyscallCategory, VirtualKernelContext, VirtualNetwork,
};

// ==========================================
// 1. Syscall Classification & Taxonomy (15 tests)
// ==========================================

#[test]
fn test_classify_read_write() {
    assert_eq!(classify_syscall(sys_nr::READ), SyscallCategory::Stateful);
    assert_eq!(classify_syscall(sys_nr::WRITE), SyscallCategory::Stateful);
}

#[test]
fn test_classify_close() {
    assert_eq!(classify_syscall(sys_nr::CLOSE), SyscallCategory::Stateful);
}

#[test]
fn test_classify_sockets() {
    assert_eq!(classify_syscall(sys_nr::SOCKET), SyscallCategory::Stateful);
    assert_eq!(classify_syscall(sys_nr::BIND), SyscallCategory::Stateful);
    assert_eq!(classify_syscall(sys_nr::LISTEN), SyscallCategory::Stateful);
    assert_eq!(classify_syscall(sys_nr::ACCEPT), SyscallCategory::Stateful);
    assert_eq!(classify_syscall(sys_nr::CONNECT), SyscallCategory::Stateful);
}

#[test]
fn test_classify_time_syscalls() {
    assert_eq!(classify_syscall(sys_nr::CLOCK_GETTIME), SyscallCategory::Nondeterministic);
    assert_eq!(classify_syscall(sys_nr::NANOSLEEP), SyscallCategory::Nondeterministic);
}

#[test]
fn test_classify_random_syscalls() {
    assert_eq!(classify_syscall(sys_nr::GETRANDOM), SyscallCategory::Nondeterministic);
}

#[test]
fn test_classify_futex_clone() {
    assert_eq!(classify_syscall(sys_nr::FUTEX), SyscallCategory::Stateful);
    assert_eq!(classify_syscall(sys_nr::CLONE), SyscallCategory::Stateful);
}

#[test]
fn test_classify_exit() {
    assert_eq!(classify_syscall(sys_nr::EXIT), SyscallCategory::Stateful);
}

#[test]
fn test_classify_epoll() {
    assert_eq!(classify_syscall(sys_nr::EPOLL_CREATE1), SyscallCategory::Stateful);
}

#[test]
fn test_classify_getpid() {
    assert_eq!(classify_syscall(sys_nr::GETPID), SyscallCategory::Nondeterministic);
}

#[test]
fn test_classify_unsupported_high_nr() {
    assert_eq!(classify_syscall(10000), SyscallCategory::Unsupported);
}

#[test]
fn test_syscall_name_read_write() {
    assert_eq!(syscall_name(sys_nr::READ), "sys_read");
    assert_eq!(syscall_name(sys_nr::WRITE), "sys_write");
}

#[test]
fn test_syscall_name_sockets() {
    assert_eq!(syscall_name(sys_nr::SOCKET), "sys_socket");
    assert_eq!(syscall_name(sys_nr::CONNECT), "sys_connect");
    assert_eq!(syscall_name(sys_nr::ACCEPT), "sys_accept");
}

#[test]
fn test_syscall_name_futex() {
    assert_eq!(syscall_name(sys_nr::FUTEX), "sys_futex");
}

#[test]
fn test_syscall_name_unknown() {
    assert_eq!(syscall_name(99999), "unknown");
}

#[test]
fn test_syscall_name_arch_prctl() {
    assert_eq!(syscall_name(sys_nr::ARCH_PRCTL), "sys_arch_prctl");
}

// ==========================================
// 2. Virtual Socket & Network Lifecycle (20 tests)
// ==========================================

#[test]
fn test_socket_addr_equality() {
    let a1 = SocketAddrV4::new(0x7f000001, 8080);
    let a2 = SocketAddrV4::new(0x7f000001, 8080);
    let a3 = SocketAddrV4::new(0x7f000001, 8081);
    assert_eq!(a1, a2);
    assert_ne!(a1, a3);
}

#[test]
fn test_socket_addr_localhost() {
    assert_eq!(SocketAddrV4::LOCALHOST, 0x7f000001);
}

#[test]
fn test_vnet_initial_state() {
    let net = VirtualNetwork::new();
    assert!(net.bindings.is_empty());
    assert!(net.connections.is_empty());
}

#[test]
fn test_vnet_allocate_conns_unique() {
    let mut net = VirtualNetwork::new();
    let c1 = net.allocate_connection();
    let c2 = net.allocate_connection();
    let c3 = net.allocate_connection();
    assert_eq!(c1, 1);
    assert_eq!(c2, 2);
    assert_eq!(c3, 3);
}

#[test]
fn test_vnet_conn_buffers_initial_empty() {
    let mut net = VirtualNetwork::new();
    let c = net.allocate_connection();
    let conn = net.connections.get(&c).unwrap();
    assert!(conn.c2s_buffer.is_empty());
    assert!(conn.s2c_buffer.is_empty());
    assert!(!conn.client_closed);
    assert!(!conn.server_closed);
}

#[test]
fn test_vnet_c2s_byte_stream() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();

    conn.c2s_buffer.extend(b"hello server");
    assert_eq!(conn.c2s_buffer.len(), 12);

    let drained: Vec<u8> = conn.c2s_buffer.drain(..5).collect();
    assert_eq!(&drained, b"hello");
    assert_eq!(conn.c2s_buffer.len(), 7);
}

#[test]
fn test_vnet_s2c_byte_stream() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();

    conn.s2c_buffer.extend(b"echo payload");
    assert_eq!(conn.s2c_buffer.len(), 12);

    let drained: Vec<u8> = conn.s2c_buffer.drain(..).collect();
    assert_eq!(&drained, b"echo payload");
    assert!(conn.s2c_buffer.is_empty());
}

#[test]
fn test_vnet_bind_and_lookup() {
    let mut net = VirtualNetwork::new();
    let addr = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 9000);
    net.bindings.insert(addr, 3);
    assert_eq!(net.bindings.get(&addr), Some(&3));
}

#[test]
fn test_vnet_lookup_unbound_port() {
    let net = VirtualNetwork::new();
    let addr = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 9999);
    assert_eq!(net.bindings.get(&addr), None);
}

#[test]
fn test_socket_state_transitions() {
    let addr = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 7000);
    let s = SocketState::Bound(addr);
    match s {
        SocketState::Bound(a) => assert_eq!(a, addr),
        _ => panic!("Expected Bound state"),
    }
}

#[test]
fn test_socket_listening_queue() {
    let addr = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 8000);
    let mut s = SocketState::Listening {
        addr,
        backlog: 10,
        incoming_queue: std::collections::VecDeque::new(),
    };

    if let SocketState::Listening { incoming_queue, .. } = &mut s {
        incoming_queue.push_back(100);
        incoming_queue.push_back(101);
        assert_eq!(incoming_queue.pop_front(), Some(100));
        assert_eq!(incoming_queue.pop_front(), Some(101));
        assert_eq!(incoming_queue.pop_front(), None);
    }
}

#[test]
fn test_socket_connected_state() {
    let local = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 40000);
    let remote = SocketAddrV4::new(SocketAddrV4::LOCALHOST, 80);
    let s = SocketState::Connected {
        local,
        remote,
        conn_id: 42,
    };
    if let SocketState::Connected { conn_id, .. } = s {
        assert_eq!(conn_id, 42);
    }
}

#[test]
fn test_socket_closed_state() {
    let s = SocketState::Closed;
    assert!(matches!(s, SocketState::Closed));
}

#[test]
fn test_partial_socket_reads() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();

    conn.c2s_buffer.extend(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    let chunk1: Vec<u8> = conn.c2s_buffer.drain(..10).collect();
    let chunk2: Vec<u8> = conn.c2s_buffer.drain(..10).collect();
    let chunk3: Vec<u8> = conn.c2s_buffer.drain(..).collect();

    assert_eq!(&chunk1, b"ABCDEFGHIJ");
    assert_eq!(&chunk2, b"KLMNOPQRST");
    assert_eq!(&chunk3, b"UVWXYZ");
}

#[test]
fn test_socket_close_client_side() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();
    conn.client_closed = true;
    assert!(conn.client_closed);
    assert!(!conn.server_closed);
}

#[test]
fn test_socket_close_server_side() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();
    conn.server_closed = true;
    assert!(conn.server_closed);
    assert!(!conn.client_closed);
}

#[test]
fn test_socket_empty_read_returns_zero() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();
    let available = conn.c2s_buffer.len().min(10);
    assert_eq!(available, 0);
}

#[test]
fn test_socket_large_packet_transfer() {
    let mut net = VirtualNetwork::new();
    let cid = net.allocate_connection();
    let conn = net.connections.get_mut(&cid).unwrap();

    let large_data = vec![0xAAu8; 65536];
    conn.c2s_buffer.extend(&large_data);
    assert_eq!(conn.c2s_buffer.len(), 65536);

    let drained: Vec<u8> = conn.c2s_buffer.drain(..).collect();
    assert_eq!(drained, large_data);
}

#[test]
fn test_vnet_multi_connection_isolation() {
    let mut net = VirtualNetwork::new();
    let c1 = net.allocate_connection();
    let c2 = net.allocate_connection();

    net.connections.get_mut(&c1).unwrap().c2s_buffer.extend(b"client1");
    net.connections.get_mut(&c2).unwrap().c2s_buffer.extend(b"client2");

    assert_eq!(net.connections.get(&c1).unwrap().c2s_buffer.as_slices().0, b"client1");
    assert_eq!(net.connections.get(&c2).unwrap().c2s_buffer.as_slices().0, b"client2");
}

#[test]
fn test_socket_state_unbound() {
    let s = SocketState::Unbound;
    assert!(matches!(s, SocketState::Unbound));
}

// ==========================================
// 3. Futex Registry (10 tests)
// ==========================================

#[test]
fn test_futex_initial_empty() {
    let mut reg = FutexRegistry::new();
    let woke = reg.wake(0x1000, 1);
    assert!(woke.is_empty());
}

#[test]
fn test_futex_wait_and_wake_single() {
    let mut reg = FutexRegistry::new();
    let t1 = ThreadId(10);
    reg.wait(0x2000, t1);
    let woke = reg.wake(0x2000, 1);
    assert_eq!(woke, vec![t1]);
}

#[test]
fn test_futex_wake_all() {
    let mut reg = FutexRegistry::new();
    for i in 1..=5 {
        reg.wait(0x3000, ThreadId(i));
    }
    let woke = reg.wake(0x3000, 10);
    assert_eq!(woke.len(), 5);
}

#[test]
fn test_futex_fifo_wake_order() {
    let mut reg = FutexRegistry::new();
    reg.wait(0x4000, ThreadId(1));
    reg.wait(0x4000, ThreadId(2));
    reg.wait(0x4000, ThreadId(3));

    assert_eq!(reg.wake(0x4000, 1), vec![ThreadId(1)]);
    assert_eq!(reg.wake(0x4000, 1), vec![ThreadId(2)]);
    assert_eq!(reg.wake(0x4000, 1), vec![ThreadId(3)]);
}

#[test]
fn test_futex_independent_addresses() {
    let mut reg = FutexRegistry::new();
    reg.wait(0x1000, ThreadId(1));
    reg.wait(0x2000, ThreadId(2));

    assert_eq!(reg.wake(0x1000, 1), vec![ThreadId(1)]);
    assert_eq!(reg.wake(0x1000, 1), Vec::<ThreadId>::new());
    assert_eq!(reg.wake(0x2000, 1), vec![ThreadId(2)]);
}

#[test]
fn test_futex_wake_count_bound() {
    let mut reg = FutexRegistry::new();
    reg.wait(0x5000, ThreadId(1));
    reg.wait(0x5000, ThreadId(2));
    reg.wait(0x5000, ThreadId(3));

    let woke = reg.wake(0x5000, 2);
    assert_eq!(woke, vec![ThreadId(1), ThreadId(2)]);
    assert_eq!(reg.wake(0x5000, 2), vec![ThreadId(3)]);
}

#[test]
fn test_futex_wake_zero_count() {
    let mut reg = FutexRegistry::new();
    reg.wait(0x6000, ThreadId(1));
    let woke = reg.wake(0x6000, 0);
    assert!(woke.is_empty());
}

#[test]
fn test_futex_repeated_waits_same_thread() {
    let mut reg = FutexRegistry::new();
    reg.wait(0x7000, ThreadId(1));
    reg.wait(0x7000, ThreadId(1));
    assert_eq!(reg.wake(0x7000, 1), vec![ThreadId(1)]);
    assert_eq!(reg.wake(0x7000, 1), vec![ThreadId(1)]);
}

#[test]
fn test_futex_large_thread_pool() {
    let mut reg = FutexRegistry::new();
    for i in 0..100 {
        reg.wait(0x8000, ThreadId(i));
    }
    let woke = reg.wake(0x8000, 50);
    assert_eq!(woke.len(), 50);
    let remaining = reg.wake(0x8000, 100);
    assert_eq!(remaining.len(), 50);
}

#[test]
fn test_futex_default() {
    let reg: FutexRegistry = Default::default();
    let mut reg = reg;
    assert!(reg.wake(0x1, 1).is_empty());
}

// ==========================================
// 4. Virtual Kernel Context & State (15 tests)
// ==========================================

#[test]
fn test_vkernel_std_descriptors() {
    let vk = VirtualKernelContext::default();
    assert!(matches!(vk.fds.get(&0), Some(FileDescriptor::StandardInput)));
    assert!(matches!(vk.fds.get(&1), Some(FileDescriptor::StandardOutput(_))));
    assert!(matches!(vk.fds.get(&2), Some(FileDescriptor::StandardError(_))));
}

#[test]
fn test_vkernel_fd_allocation_monotonic() {
    let mut vk = VirtualKernelContext::default();
    let fd1 = vk.alloc_fd(FileDescriptor::StandardInput);
    let fd2 = vk.alloc_fd(FileDescriptor::StandardInput);
    assert_eq!(fd1, 3);
    assert_eq!(fd2, 4);
}

#[test]
fn test_vkernel_prng_determinism() {
    let mut vk1 = VirtualKernelContext::default();
    let mut vk2 = VirtualKernelContext::default();

    for _ in 0..100 {
        assert_eq!(vk1.deterministic_random_u64(), vk2.deterministic_random_u64());
    }
}

#[test]
fn test_vkernel_prng_non_zero_progression() {
    let mut vk = VirtualKernelContext::default();
    let r1 = vk.deterministic_random_u64();
    let r2 = vk.deterministic_random_u64();
    assert_ne!(r1, 0);
    assert_ne!(r1, r2);
}

#[test]
fn test_vkernel_initial_memory_pointers() {
    let vk = VirtualKernelContext::default();
    assert_eq!(vk.brk_current, 0x600000);
    assert_eq!(vk.mmap_next, 0x700000000000);
}

#[test]
fn test_vkernel_initial_exit_code() {
    let vk = VirtualKernelContext::default();
    assert_eq!(vk.exit_code, None);
}

#[test]
fn test_vkernel_stdout_capture() {
    let mut vk = VirtualKernelContext::default();
    if let Some(FileDescriptor::StandardOutput(buf)) = vk.fds.get_mut(&1) {
        buf.extend_from_slice(b"hello stdout\n");
    }
    if let Some(FileDescriptor::StandardOutput(buf)) = vk.fds.get(&1) {
        assert_eq!(buf, b"hello stdout\n");
    }
}

#[test]
fn test_vkernel_stderr_capture() {
    let mut vk = VirtualKernelContext::default();
    if let Some(FileDescriptor::StandardError(buf)) = vk.fds.get_mut(&2) {
        buf.extend_from_slice(b"fatal error\n");
    }
    if let Some(FileDescriptor::StandardError(buf)) = vk.fds.get(&2) {
        assert_eq!(buf, b"fatal error\n");
    }
}

#[test]
fn test_vkernel_socket_fd_creation() {
    let mut vk = VirtualKernelContext::default();
    let fd = vk.alloc_fd(FileDescriptor::Socket {
        domain: 2,
        sock_type: 1,
        protocol: 0,
        state: SocketState::Unbound,
    });
    assert_eq!(fd, 3);
    assert!(matches!(vk.fds.get(&fd), Some(FileDescriptor::Socket { .. })));
}

#[test]
fn test_vkernel_fd_removal() {
    let mut vk = VirtualKernelContext::default();
    let fd = vk.alloc_fd(FileDescriptor::StandardInput);
    assert!(vk.fds.contains_key(&fd));
    vk.fds.remove(&fd);
    assert!(!vk.fds.contains_key(&fd));
}

#[test]
fn test_vkernel_clear_child_tid_default() {
    let vk = VirtualKernelContext::default();
    assert_eq!(vk.clear_child_tid, 0);
}

#[test]
fn test_vkernel_virtual_time_default() {
    let vk = VirtualKernelContext::default();
    assert_eq!(vk.virtual_time, crucible_core::VirtualTime(1_700_000_000_000_000_000));
}

#[test]
fn test_vkernel_brk_expansion() {
    let mut vk = VirtualKernelContext::default();
    vk.brk_current += 0x10000;
    assert_eq!(vk.brk_current, 0x610000);
}

#[test]
fn test_vkernel_mmap_page_advance() {
    let mut vk = VirtualKernelContext::default();
    let initial = vk.mmap_next;
    vk.mmap_next += 0x4000;
    assert_eq!(vk.mmap_next - initial, 16384);
}

#[test]
fn test_vkernel_set_exit_code() {
    let mut vk = VirtualKernelContext::default();
    vk.exit_code = Some(42);
    assert_eq!(vk.exit_code, Some(42));
}
