use std::arch::asm;

#[inline(always)]
unsafe fn syscall1(nr: usize, a0: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        inout("rax") nr => ret,
        in("rdi") a0,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall2(nr: usize, a0: usize, a1: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        inout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: usize, a0: usize, a1: usize, a2: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        inout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall4(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        inout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

#[inline(always)]
unsafe fn syscall5(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let ret: usize;
    asm!(
        "syscall",
        inout("rax") nr => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        in("r8") a4,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_CLOSE: usize = 3;
const SYS_SOCKET: usize = 41;
const SYS_CONNECT: usize = 42;
const SYS_ACCEPT: usize = 43;
const SYS_BIND: usize = 49;
const SYS_LISTEN: usize = 50;
const SYS_GETSOCKNAME: usize = 51;
const SYS_GETPEERNAME: usize = 52;
const SYS_SETSOCKOPT: usize = 54;
const SYS_GETSOCKOPT: usize = 55;
const SYS_FCNTL: usize = 72;
const SYS_EPOLL_WAIT: usize = 232;
const SYS_EPOLL_CTL: usize = 233;
const SYS_EPOLL_CREATE1: usize = 291;

const EPOLLIN: u32 = 0x0001;
const EPOLLOUT: u32 = 0x0004;
const EPOLL_CTL_ADD: usize = 1;
const EPOLL_CTL_DEL: usize = 2;
const EPOLL_CTL_MOD: usize = 3;

#[derive(Copy, Clone)]
#[repr(C, packed)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

// In-memory key-value store for Redis server
struct RedisStore {
    keys: [&'static [u8]; 16],
    vals: [Vec<u8>; 16],
    len: usize,
}

impl RedisStore {
    fn new() -> Self {
        Self {
            keys: [&[]; 16],
            vals: Default::default(),
            len: 0,
        }
    }

    fn set(&mut self, key: &'static [u8], val: Vec<u8>) {
        for i in 0..self.len {
            if self.keys[i] == key {
                self.vals[i] = val;
                return;
            }
        }
        if self.len < 16 {
            self.keys[self.len] = key;
            self.vals[self.len] = val;
            self.len += 1;
        }
    }

    fn get(&self, key: &[u8]) -> Option<&[u8]> {
        for i in 0..self.len {
            if self.keys[i] == key {
                return Some(&self.vals[i]);
            }
        }
        None
    }

    fn incr(&mut self, key: &'static [u8]) -> i64 {
        for i in 0..self.len {
            if self.keys[i] == key {
                let s = std::str::from_utf8(&self.vals[i]).unwrap_or("0");
                let num: i64 = s.parse().unwrap_or(0) + 1;
                self.vals[i] = num.to_string().into_bytes();
                return num;
            }
        }
        self.set(key, b"1".to_vec());
        1
    }
}

fn main() {
    unsafe {
        // 1. Create Server Socket: socket(AF_INET=2, SOCK_STREAM=1, 0)
        let srv_sock = syscall3(SYS_SOCKET, 2, 1, 0) as i32;
        assert!(srv_sock >= 0, "srv socket failed");

        // 2. Set SO_REUSEADDR
        let optval: u32 = 1;
        let s_res = syscall5(
            SYS_SETSOCKOPT,
            srv_sock as usize,
            1, // SOL_SOCKET
            2, // SO_REUSEADDR
            &optval as *const _ as usize,
            4,
        );
        assert_eq!(s_res, 0, "setsockopt failed");

        // 3. Bind to 127.0.0.1:6379
        let srv_addr = SockAddrIn {
            sin_family: 2,
            sin_port: (6379u16).to_be(),
            sin_addr: 0x7f000001u32.to_be(),
            sin_zero: [0; 8],
        };
        let b_res = syscall3(
            SYS_BIND,
            srv_sock as usize,
            &srv_addr as *const _ as usize,
            16,
        );
        assert_eq!(b_res, 0, "bind failed");

        // 4. Listen
        let l_res = syscall2(SYS_LISTEN, srv_sock as usize, 128);
        assert_eq!(l_res, 0, "listen failed");

        // Verify getsockname and getsockopt
        let mut local_addr = SockAddrIn { sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8] };
        let mut addr_len = 16u32;
        let gsn_res = syscall3(SYS_GETSOCKNAME, srv_sock as usize, &mut local_addr as *mut _ as usize, &mut addr_len as *mut _ as usize);
        assert_eq!(gsn_res, 0, "getsockname failed");
        assert_eq!(local_addr.sin_port, (6379u16).to_be());

        let mut get_opt: u32 = 0;
        let mut opt_len = 4u32;
        let gso_res = syscall5(SYS_GETSOCKOPT, srv_sock as usize, 1, 2, &mut get_opt as *mut _ as usize, &mut opt_len as *mut _ as usize);
        assert_eq!(gso_res, 0, "getsockopt failed");
        assert_eq!(get_opt, 1);

        // 5. Create Epoll Instance
        let epfd = syscall1(SYS_EPOLL_CREATE1, 0) as i32;
        assert!(epfd >= 0, "epoll_create1 failed");

        // 6. Register Server Socket with Epoll
        let mut ev = EpollEvent {
            events: EPOLLIN,
            data: srv_sock as u64,
        };
        let ctl_res = syscall4(
            SYS_EPOLL_CTL,
            epfd as usize,
            EPOLL_CTL_ADD,
            srv_sock as usize,
            &mut ev as *mut _ as usize,
        );
        assert_eq!(ctl_res, 0, "epoll_ctl add srv failed");

        // 7. Create Client Socket
        let cli_sock = syscall3(SYS_SOCKET, 2, 1, 0) as i32;
        assert!(cli_sock >= 0, "cli socket failed");

        // 8. Connect Client Socket to 127.0.0.1:6379
        let conn_res = syscall3(
            SYS_CONNECT,
            cli_sock as usize,
            &srv_addr as *const _ as usize,
            16,
        );
        assert_eq!(conn_res, 0, "connect failed");

        let mut peer_addr = SockAddrIn { sin_family: 0, sin_port: 0, sin_addr: 0, sin_zero: [0; 8] };
        let gpn_res = syscall3(SYS_GETPEERNAME, cli_sock as usize, &mut peer_addr as *mut _ as usize, &mut addr_len as *mut _ as usize);
        assert_eq!(gpn_res, 0, "getpeername failed");
        assert_eq!(peer_addr.sin_port, (6379u16).to_be());

        // 9. Poll Epoll for incoming connection on Server Socket
        let mut events = [EpollEvent { events: 0, data: 0 }; 4];
        let n = syscall4(
            SYS_EPOLL_WAIT,
            epfd as usize,
            events.as_mut_ptr() as usize,
            4,
            100, // timeout 100ms
        );
        assert_eq!(n, 1, "expected 1 ready event on srv_sock");
        let d0 = events[0].data;
        assert_eq!(d0, srv_sock as u64);

        // 10. Accept Client Connection
        let accepted_sock = syscall3(SYS_ACCEPT, srv_sock as usize, 0, 0) as i32;
        assert!(accepted_sock >= 0, "accept failed");

        // 11. Set accepted socket non-blocking
        let fcntl_res = syscall3(SYS_FCNTL, accepted_sock as usize, 4, 0x800); // F_SETFL, O_NONBLOCK
        assert_eq!(fcntl_res, 0, "fcntl setfl failed");

        // 12. Register accepted socket with epoll
        let mut cli_ev = EpollEvent {
            events: EPOLLIN,
            data: accepted_sock as u64,
        };
        let ctl_res2 = syscall4(
            SYS_EPOLL_CTL,
            epfd as usize,
            EPOLL_CTL_ADD,
            accepted_sock as usize,
            &mut cli_ev as *mut _ as usize,
        );
        assert_eq!(ctl_res2, 0, "epoll_ctl add client failed");

        let mut store = RedisStore::new();
        let mut recv_buf = [0u8; 256];

        // --- Command 1: PING -> +PONG\r\n ---
        let ping_cmd = b"*1\r\n$4\r\nPING\r\n";
        let w = syscall3(SYS_WRITE, cli_sock as usize, ping_cmd.as_ptr() as usize, ping_cmd.len());
        assert_eq!(w, ping_cmd.len());

        let wait1 = syscall4(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, 4, 100);
        assert_eq!(wait1, 1);
        let d1 = events[0].data;
        assert_eq!(d1, accepted_sock as u64);

        let r = syscall3(SYS_READ, accepted_sock as usize, recv_buf.as_mut_ptr() as usize, recv_buf.len());
        assert!(r > 0);
        let resp_pong = b"+PONG\r\n";
        let w = syscall3(SYS_WRITE, accepted_sock as usize, resp_pong.as_ptr() as usize, resp_pong.len());
        assert_eq!(w, resp_pong.len());

        let mut cli_buf = [0u8; 64];
        let cr = syscall3(SYS_READ, cli_sock as usize, cli_buf.as_mut_ptr() as usize, cli_buf.len());
        assert_eq!(&cli_buf[..cr], resp_pong);

        // --- Command 2: SET mykey myval -> +OK\r\n ---
        let set_cmd = b"*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$5\r\nmyval\r\n";
        syscall3(SYS_WRITE, cli_sock as usize, set_cmd.as_ptr() as usize, set_cmd.len());

        let wait2 = syscall4(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, 4, 100);
        assert_eq!(wait2, 1);

        let r = syscall3(SYS_READ, accepted_sock as usize, recv_buf.as_mut_ptr() as usize, recv_buf.len());
        assert!(r > 0);
        store.set(b"mykey", b"myval".to_vec());
        let resp_ok = b"+OK\r\n";
        syscall3(SYS_WRITE, accepted_sock as usize, resp_ok.as_ptr() as usize, resp_ok.len());

        let cr = syscall3(SYS_READ, cli_sock as usize, cli_buf.as_mut_ptr() as usize, cli_buf.len());
        assert_eq!(&cli_buf[..cr], resp_ok);

        // --- Command 3: GET mykey -> $5\r\nmyval\r\n ---
        let get_cmd = b"*2\r\n$3\r\nGET\r\n$5\r\nmykey\r\n";
        syscall3(SYS_WRITE, cli_sock as usize, get_cmd.as_ptr() as usize, get_cmd.len());

        let wait3 = syscall4(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, 4, 100);
        assert_eq!(wait3, 1);

        let r = syscall3(SYS_READ, accepted_sock as usize, recv_buf.as_mut_ptr() as usize, recv_buf.len());
        assert!(r > 0);
        let val = store.get(b"mykey").unwrap();
        assert_eq!(val, b"myval");
        let resp_val = b"$5\r\nmyval\r\n";
        syscall3(SYS_WRITE, accepted_sock as usize, resp_val.as_ptr() as usize, resp_val.len());

        let cr = syscall3(SYS_READ, cli_sock as usize, cli_buf.as_mut_ptr() as usize, cli_buf.len());
        assert_eq!(&cli_buf[..cr], resp_val);

        // --- Command 4: INCR mycounter -> :1\r\n ---
        let incr_cmd1 = b"*2\r\n$4\r\nINCR\r\n$9\r\nmycounter\r\n";
        syscall3(SYS_WRITE, cli_sock as usize, incr_cmd1.as_ptr() as usize, incr_cmd1.len());

        let wait4 = syscall4(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, 4, 100);
        assert_eq!(wait4, 1);

        syscall3(SYS_READ, accepted_sock as usize, recv_buf.as_mut_ptr() as usize, recv_buf.len());
        let n1 = store.incr(b"mycounter");
        assert_eq!(n1, 1);
        let resp_incr1 = b":1\r\n";
        syscall3(SYS_WRITE, accepted_sock as usize, resp_incr1.as_ptr() as usize, resp_incr1.len());

        let cr = syscall3(SYS_READ, cli_sock as usize, cli_buf.as_mut_ptr() as usize, cli_buf.len());
        assert_eq!(&cli_buf[..cr], resp_incr1);

        // --- Command 5: INCR mycounter -> :2\r\n ---
        syscall3(SYS_WRITE, cli_sock as usize, incr_cmd1.as_ptr() as usize, incr_cmd1.len());
        let wait5 = syscall4(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, 4, 100);
        assert_eq!(wait5, 1);

        syscall3(SYS_READ, accepted_sock as usize, recv_buf.as_mut_ptr() as usize, recv_buf.len());
        let n2 = store.incr(b"mycounter");
        assert_eq!(n2, 2);
        let resp_incr2 = b":2\r\n";
        syscall3(SYS_WRITE, accepted_sock as usize, resp_incr2.as_ptr() as usize, resp_incr2.len());

        let cr = syscall3(SYS_READ, cli_sock as usize, cli_buf.as_mut_ptr() as usize, cli_buf.len());
        assert_eq!(&cli_buf[..cr], resp_incr2);

        // --- Command 6: GET nonexistent -> $-1\r\n ---
        let get_none = b"*2\r\n$3\r\nGET\r\n$4\r\nnone\r\n";
        syscall3(SYS_WRITE, cli_sock as usize, get_none.as_ptr() as usize, get_none.len());
        let wait6 = syscall4(SYS_EPOLL_WAIT, epfd as usize, events.as_mut_ptr() as usize, 4, 100);
        assert_eq!(wait6, 1);

        syscall3(SYS_READ, accepted_sock as usize, recv_buf.as_mut_ptr() as usize, recv_buf.len());
        let resp_null = b"$-1\r\n";
        syscall3(SYS_WRITE, accepted_sock as usize, resp_null.as_ptr() as usize, resp_null.len());

        let cr = syscall3(SYS_READ, cli_sock as usize, cli_buf.as_mut_ptr() as usize, cli_buf.len());
        assert_eq!(&cli_buf[..cr], resp_null);

        // Test EPOLL_CTL_MOD and EPOLL_CTL_DEL
        let mut mod_ev = EpollEvent {
            events: EPOLLIN | EPOLLOUT,
            data: accepted_sock as u64,
        };
        let ctl_mod = syscall4(
            SYS_EPOLL_CTL,
            epfd as usize,
            EPOLL_CTL_MOD,
            accepted_sock as usize,
            &mut mod_ev as *mut _ as usize,
        );
        assert_eq!(ctl_mod, 0, "epoll_ctl mod failed");

        let ctl_del = syscall4(
            SYS_EPOLL_CTL,
            epfd as usize,
            EPOLL_CTL_DEL,
            accepted_sock as usize,
            0,
        );
        assert_eq!(ctl_del, 0, "epoll_ctl del failed");

        // Clean up
        syscall1(SYS_CLOSE, cli_sock as usize);
        syscall1(SYS_CLOSE, accepted_sock as usize);
        syscall1(SYS_CLOSE, srv_sock as usize);
        syscall1(SYS_CLOSE, epfd as usize);
    }
}
