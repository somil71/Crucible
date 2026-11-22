//! Deterministic Virtual WASI implementation and Crucible host bindings.
//!
//! Provides zero-leakage deterministic host implementations for:
//! - WASI Preview 1 (`wasi_snapshot_preview1`): clocks, random entropy, I/O, process control.
//! - Crucible host imports (`crucible`): direct high-performance consensus messaging and time.

use std::collections::VecDeque;
use rand::RngCore;
use rand_chacha::ChaCha8Rng;
use rand::SeedableRng;
use wasmtime::*;

/// Error codes matching WASI standard errno.
pub mod wasi_errno {
    pub const SUCCESS: i32 = 0;
    pub const EBADF: i32 = 8;
    pub const EAGAIN: i32 = 6;
    pub const EINVAL: i32 = 28;
}

/// Node context stored inside Wasmtime's `Store<WasmHostContext>`.
pub struct WasmHostContext {
    pub node_id: u32,
    pub virtual_time_ns: u64,
    pub prng: ChaCha8Rng,
    pub inbox: VecDeque<Vec<u8>>,
    pub outbox: VecDeque<(u32, Vec<u8>)>,
    pub stdout_buf: Vec<u8>,
    pub stderr_buf: Vec<u8>,
    pub step_counter: u64,
    pub total_fuel_consumed: u64,
    pub exit_code: Option<i32>,
}

impl WasmHostContext {
    pub fn new(node_id: u32, seed: u64) -> Self {
        Self {
            node_id,
            virtual_time_ns: 0,
            prng: ChaCha8Rng::seed_from_u64(seed),
            inbox: VecDeque::new(),
            outbox: VecDeque::new(),
            stdout_buf: Vec::new(),
            stderr_buf: Vec::new(),
            step_counter: 0,
            total_fuel_consumed: 0,
            exit_code: None,
        }
    }
}

/// Register both WASI Preview 1 and Crucible host functions to Linker.
pub fn register_wasi_and_host_imports(linker: &mut Linker<WasmHostContext>) -> anyhow::Result<()> {
    register_wasi_preview1(linker)?;
    register_crucible_imports(linker)?;
    Ok(())
}

/// Register standard `wasi_snapshot_preview1` functions with 100% deterministic implementations.
fn register_wasi_preview1(linker: &mut Linker<WasmHostContext>) -> anyhow::Result<()> {
    // clock_time_get(id: u32, precision: u64, time_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "clock_time_get",
        |mut caller: Caller<'_, WasmHostContext>, _id: i32, _precision: i64, time_ptr: i32| -> i32 {
            let vtime = caller.data().virtual_time_ns;
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };
            let (data, _) = mem.data_and_store_mut(&mut caller);
            let offset = time_ptr as usize;
            if offset + 8 > data.len() {
                return wasi_errno::EINVAL;
            }
            data[offset..offset + 8].copy_from_slice(&vtime.to_le_bytes());
            wasi_errno::SUCCESS
        },
    )?;

    // clock_res_get(id: u32, res_ptr: u32) -> u32 (1 ns resolution)
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "clock_res_get",
        |mut caller: Caller<'_, WasmHostContext>, _id: i32, res_ptr: i32| -> i32 {
            let res: u64 = 1; // 1 ns
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };
            let (data, _) = mem.data_and_store_mut(&mut caller);
            let offset = res_ptr as usize;
            if offset + 8 > data.len() {
                return wasi_errno::EINVAL;
            }
            data[offset..offset + 8].copy_from_slice(&res.to_le_bytes());
            wasi_errno::SUCCESS
        },
    )?;

    // random_get(buf_ptr: u32, buf_len: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "random_get",
        |mut caller: Caller<'_, WasmHostContext>, buf_ptr: i32, buf_len: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };
            let start = buf_ptr as usize;
            let len = buf_len as usize;
            let (data, store) = mem.data_and_store_mut(&mut caller);
            if start + len > data.len() {
                return wasi_errno::EINVAL;
            }
            store.prng.fill_bytes(&mut data[start..start + len]);
            wasi_errno::SUCCESS
        },
    )?;

    // sched_yield() -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "sched_yield",
        |_caller: Caller<'_, WasmHostContext>| -> i32 {
            wasi_errno::SUCCESS
        },
    )?;

    // proc_exit(rval: u32)
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "proc_exit",
        |mut caller: Caller<'_, WasmHostContext>, rval: i32| {
            caller.data_mut().exit_code = Some(rval);
        },
    )?;

    // fd_write(fd: u32, iovs_ptr: u32, iovs_len: u32, nwritten_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_write",
        |mut caller: Caller<'_, WasmHostContext>, fd: i32, iovs_ptr: i32, iovs_len: i32, nwritten_ptr: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };

            let mut total_written: usize = 0;
            let iovs_base = iovs_ptr as usize;
            let iovs_count = iovs_len as usize;

            for i in 0..iovs_count {
                let entry_offset = iovs_base + i * 8;
                let (buf_ptr, buf_len) = {
                    let data = mem.data(&caller);
                    if entry_offset + 8 > data.len() {
                        return wasi_errno::EINVAL;
                    }
                    let ptr = u32::from_le_bytes(data[entry_offset..entry_offset + 4].try_into().unwrap()) as usize;
                    let len = u32::from_le_bytes(data[entry_offset + 4..entry_offset + 8].try_into().unwrap()) as usize;
                    (ptr, len)
                };

                let slice_bytes = {
                    let data = mem.data(&caller);
                    if buf_ptr + buf_len > data.len() {
                        return wasi_errno::EINVAL;
                    }
                    data[buf_ptr..buf_ptr + buf_len].to_vec()
                };

                match fd {
                    1 => caller.data_mut().stdout_buf.extend_from_slice(&slice_bytes),
                    2 => caller.data_mut().stderr_buf.extend_from_slice(&slice_bytes),
                    dest_node if dest_node >= 3 => {
                        caller.data_mut().outbox.push_back((dest_node as u32, slice_bytes));
                    }
                    _ => return wasi_errno::EBADF,
                }
                total_written += buf_len;
            }

            let (data, _) = mem.data_and_store_mut(&mut caller);
            let nw_offset = nwritten_ptr as usize;
            if nw_offset + 4 <= data.len() {
                data[nw_offset..nw_offset + 4].copy_from_slice(&(total_written as u32).to_le_bytes());
            }

            wasi_errno::SUCCESS
        },
    )?;

    // fd_read(fd: u32, iovs_ptr: u32, iovs_len: u32, nread_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_read",
        |mut caller: Caller<'_, WasmHostContext>, _fd: i32, iovs_ptr: i32, iovs_len: i32, nread_ptr: i32| -> i32 {
            let msg = match caller.data_mut().inbox.pop_front() {
                Some(m) => m,
                None => {
                    let mem = match caller.get_export("memory") {
                        Some(Extern::Memory(m)) => m,
                        _ => return wasi_errno::EINVAL,
                    };
                    let (data, _) = mem.data_and_store_mut(&mut caller);
                    let nr_offset = nread_ptr as usize;
                    if nr_offset + 4 <= data.len() {
                        data[nr_offset..nr_offset + 4].copy_from_slice(&0u32.to_le_bytes());
                    }
                    return wasi_errno::EAGAIN;
                }
            };

            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };

            let mut msg_remaining = &msg[..];
            let mut total_read: usize = 0;
            let iovs_base = iovs_ptr as usize;
            let iovs_count = iovs_len as usize;

            for i in 0..iovs_count {
                if msg_remaining.is_empty() {
                    break;
                }
                let entry_offset = iovs_base + i * 8;
                let (buf_ptr, buf_len) = {
                    let data = mem.data(&caller);
                    if entry_offset + 8 > data.len() {
                        return wasi_errno::EINVAL;
                    }
                    let ptr = u32::from_le_bytes(data[entry_offset..entry_offset + 4].try_into().unwrap()) as usize;
                    let len = u32::from_le_bytes(data[entry_offset + 4..entry_offset + 8].try_into().unwrap()) as usize;
                    (ptr, len)
                };

                let to_copy = buf_len.min(msg_remaining.len());
                let (data, _) = mem.data_and_store_mut(&mut caller);
                if buf_ptr + to_copy > data.len() {
                    return wasi_errno::EINVAL;
                }
                data[buf_ptr..buf_ptr + to_copy].copy_from_slice(&msg_remaining[..to_copy]);
                total_read += to_copy;
                msg_remaining = &msg_remaining[to_copy..];
            }

            let (data, _) = mem.data_and_store_mut(&mut caller);
            let nr_offset = nread_ptr as usize;
            if nr_offset + 4 <= data.len() {
                data[nr_offset..nr_offset + 4].copy_from_slice(&(total_read as u32).to_le_bytes());
            }

            wasi_errno::SUCCESS
        },
    )?;

    // fd_fdstat_get(fd: u32, buf_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_fdstat_get",
        |mut caller: Caller<'_, WasmHostContext>, _fd: i32, buf_ptr: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };
            let (data, _) = mem.data_and_store_mut(&mut caller);
            let offset = buf_ptr as usize;
            if offset + 24 <= data.len() {
                data[offset..offset + 24].fill(0);
            }
            wasi_errno::SUCCESS
        },
    )?;

    // fd_close(fd: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_close",
        |_caller: Caller<'_, WasmHostContext>, _fd: i32| -> i32 {
            wasi_errno::SUCCESS
        },
    )?;

    // fd_seek(fd: u32, offset: i64, whence: u32, newoffset_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_seek",
        |_caller: Caller<'_, WasmHostContext>, _fd: i32, _offset: i64, _whence: i32, _newoffset_ptr: i32| -> i32 {
            wasi_errno::SUCCESS
        },
    )?;

    // environ_sizes_get(environ_count_ptr: u32, environ_buf_size_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_sizes_get",
        |mut caller: Caller<'_, WasmHostContext>, count_ptr: i32, buf_size_ptr: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };
            let (data, _) = mem.data_and_store_mut(&mut caller);
            let c_off = count_ptr as usize;
            let b_off = buf_size_ptr as usize;
            if c_off + 4 <= data.len() {
                data[c_off..c_off + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            if b_off + 4 <= data.len() {
                data[b_off..b_off + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            wasi_errno::SUCCESS
        },
    )?;

    // environ_get(environ_ptr: u32, environ_buf_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_get",
        |_caller: Caller<'_, WasmHostContext>, _env_ptr: i32, _env_buf_ptr: i32| -> i32 {
            wasi_errno::SUCCESS
        },
    )?;

    // args_sizes_get(argc_ptr: u32, argv_buf_size_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "args_sizes_get",
        |mut caller: Caller<'_, WasmHostContext>, argc_ptr: i32, argv_buf_size_ptr: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return wasi_errno::EINVAL,
            };
            let (data, _) = mem.data_and_store_mut(&mut caller);
            let c_off = argc_ptr as usize;
            let b_off = argv_buf_size_ptr as usize;
            if c_off + 4 <= data.len() {
                data[c_off..c_off + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            if b_off + 4 <= data.len() {
                data[b_off..b_off + 4].copy_from_slice(&0u32.to_le_bytes());
            }
            wasi_errno::SUCCESS
        },
    )?;

    // args_get(argv_ptr: u32, argv_buf_ptr: u32) -> u32
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "args_get",
        |_caller: Caller<'_, WasmHostContext>, _argv_ptr: i32, _argv_buf_ptr: i32| -> i32 {
            wasi_errno::SUCCESS
        },
    )?;

    Ok(())
}

/// Register dedicated `crucible` module functions for high-speed deterministic consensus simulation.
fn register_crucible_imports(linker: &mut Linker<WasmHostContext>) -> anyhow::Result<()> {
    // crucible_node_id() -> u32
    linker.func_wrap("crucible", "crucible_node_id", |caller: Caller<'_, WasmHostContext>| -> i32 {
        caller.data().node_id as i32
    })?;

    // crucible_virtual_time() -> u64
    linker.func_wrap("crucible", "crucible_virtual_time", |caller: Caller<'_, WasmHostContext>| -> i64 {
        caller.data().virtual_time_ns as i64
    })?;

    // crucible_rand_u64() -> u64
    linker.func_wrap("crucible", "crucible_rand_u64", |mut caller: Caller<'_, WasmHostContext>| -> i64 {
        caller.data_mut().prng.next_u64() as i64
    })?;

    // crucible_send_msg(dest_node: u32, data_ptr: u32, data_len: u32) -> i32 (0 = success)
    linker.func_wrap(
        "crucible",
        "crucible_send_msg",
        |mut caller: Caller<'_, WasmHostContext>, dest_node: i32, data_ptr: i32, data_len: i32| -> i32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return -1,
            };
            let start = data_ptr as usize;
            let len = data_len as usize;
            let data = mem.data(&caller);
            if start + len > data.len() {
                return -2;
            }
            let payload = data[start..start + len].to_vec();
            caller.data_mut().outbox.push_back((dest_node as u32, payload));
            0
        },
    )?;

    // crucible_recv_msg(buf_ptr: u32, max_len: u32) -> i32 (returns bytes written or -1 if empty)
    linker.func_wrap(
        "crucible",
        "crucible_recv_msg",
        |mut caller: Caller<'_, WasmHostContext>, buf_ptr: i32, max_len: i32| -> i32 {
            let msg = match caller.data_mut().inbox.pop_front() {
                Some(m) => m,
                None => return -1,
            };
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return -2,
            };
            let start = buf_ptr as usize;
            let max = max_len as usize;
            let copy_len = msg.len().min(max);
            let (data, _) = mem.data_and_store_mut(&mut caller);
            if start + copy_len > data.len() {
                return -3;
            }
            data[start..start + copy_len].copy_from_slice(&msg[..copy_len]);
            copy_len as i32
        },
    )?;

    // crucible_log(msg_ptr: u32, msg_len: u32)
    linker.func_wrap(
        "crucible",
        "crucible_log",
        |mut caller: Caller<'_, WasmHostContext>, msg_ptr: i32, msg_len: i32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(m)) => m,
                _ => return,
            };
            let start = msg_ptr as usize;
            let len = msg_len as usize;
            let maybe_msg = {
                let data = mem.data(&caller);
                if start + len <= data.len() {
                    Some(data[start..start + len].to_vec())
                } else {
                    None
                }
            };
            if let Some(msg_bytes) = maybe_msg {
                caller.data_mut().stdout_buf.extend_from_slice(&msg_bytes);
            }
        },
    )?;

    Ok(())
}
