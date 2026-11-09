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

const SYS_READ: usize = 0;
const SYS_WRITE: usize = 1;
const SYS_CLOSE: usize = 3;
const SYS_SOCKET: usize = 41;
const SYS_CONNECT: usize = 42;
const SYS_ACCEPT: usize = 43;
const SYS_BIND: usize = 49;
const SYS_LISTEN: usize = 50;

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [u8; 8],
}

fn main() {
    unsafe {
        // 1. Create Server Socket: socket(AF_INET=2, SOCK_STREAM=1, 0)
        let srv_sock = syscall3(SYS_SOCKET, 2, 1, 0) as i32;
        assert!(srv_sock >= 0, "socket failed");

        // 2. Bind to 127.0.0.1:9099
        let srv_addr = SockAddrIn {
            sin_family: 2,
            sin_port: (9099u16).to_be(),
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

        // 3. Listen(srv_sock, 10)
        let l_res = syscall2(SYS_LISTEN, srv_sock as usize, 10);
        assert_eq!(l_res, 0, "listen failed");

        // 4. Create Client Socket
        let cli_sock = syscall3(SYS_SOCKET, 2, 1, 0) as i32;
        assert!(cli_sock >= 0, "client socket failed");

        // 5. Connect Client Socket to 127.0.0.1:9099
        let c_res = syscall3(
            SYS_CONNECT,
            cli_sock as usize,
            &srv_addr as *const _ as usize,
            16,
        );
        assert_eq!(c_res, 0, "connect failed");

        // 6. Accept Connection on Server Socket
        let accepted_sock = syscall3(SYS_ACCEPT, srv_sock as usize, 0, 0) as i32;
        assert!(accepted_sock >= 0, "accept failed");

        // 7. Loopback Echo Message Exchange (100 rounds)
        let msg = b"crucible_ping_message\n";
        let mut recv_buf = [0u8; 32];

        for _ in 0..100 {
            // Client writes msg
            let w1 = syscall3(
                SYS_WRITE,
                cli_sock as usize,
                msg.as_ptr() as usize,
                msg.len(),
            );
            assert_eq!(w1, msg.len());

            // Server reads msg
            let r1 = syscall3(
                SYS_READ,
                accepted_sock as usize,
                recv_buf.as_mut_ptr() as usize,
                msg.len(),
            );
            assert_eq!(r1, msg.len());

            // Server echoes back to client
            let w2 = syscall3(
                SYS_WRITE,
                accepted_sock as usize,
                recv_buf.as_ptr() as usize,
                r1,
            );
            assert_eq!(w2, r1);

            // Client reads echoed response
            let r2 = syscall3(
                SYS_READ,
                cli_sock as usize,
                recv_buf.as_mut_ptr() as usize,
                msg.len(),
            );
            assert_eq!(r2, msg.len());
        }

        // 8. Clean up Sockets
        syscall1(SYS_CLOSE, cli_sock as usize);
        syscall1(SYS_CLOSE, accepted_sock as usize);
        syscall1(SYS_CLOSE, srv_sock as usize);
    }
}
