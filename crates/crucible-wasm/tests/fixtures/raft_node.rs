//! Minimal, zero-dependency, deterministic Raft consensus node compiled to wasm32-wasip1.

#![no_std]

#[link(wasm_import_module = "crucible")]
extern "C" {
    fn crucible_virtual_time() -> i64;
    fn crucible_rand_u64() -> i64;
    fn crucible_send_msg(dest_node: i32, data_ptr: i32, data_len: i32) -> i32;
    fn crucible_recv_msg(buf_ptr: i32, max_len: i32) -> i32;
}

#[panic_handler]
fn handle_panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

const MSG_REQUEST_VOTE: u8 = 1;
const MSG_REQUEST_VOTE_REPLY: u8 = 2;
const MSG_APPEND_ENTRIES: u8 = 3;
const MSG_APPEND_ENTRIES_REPLY: u8 = 4;

const ROLE_FOLLOWER: u8 = 0;
const ROLE_CANDIDATE: u8 = 1;
const ROLE_LEADER: u8 = 2;

const MAX_LOG: usize = 128;
const MAX_NODES: usize = 8;
const MAX_KV: usize = 16;

#[derive(Clone, Copy)]
struct LogEntry {
    term: u32,
    index: u32,
    key: u32,
    val: u32,
}

static mut NODE_ID: u32 = 0;
static mut CLUSTER_SIZE: u32 = 0;
static mut CURRENT_TERM: u32 = 0;
static mut VOTED_FOR: u32 = 0; // 0 = None
static mut ROLE: u8 = ROLE_FOLLOWER;

static mut ELECTION_DEADLINE_NS: u64 = 0;
static mut HEARTBEAT_DEADLINE_NS: u64 = 0;

static mut VOTES_GRANTED_MASK: u32 = 0;

static mut LOG_LEN: usize = 0;
static mut LOG: [LogEntry; MAX_LOG] = [LogEntry { term: 0, index: 0, key: 0, val: 0 }; MAX_LOG];

static mut COMMIT_INDEX: u32 = 0;
static mut LAST_APPLIED: u32 = 0;

static mut NEXT_INDEX: [u32; MAX_NODES] = [1; MAX_NODES];
static mut MATCH_INDEX: [u32; MAX_NODES] = [0; MAX_NODES];

static mut KV_STORE: [u32; MAX_KV] = [0; MAX_KV];

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    let b = [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]];
    u32::from_le_bytes(b)
}

fn reset_election_timeout(now_ns: u64) {
    let rand = unsafe { crucible_rand_u64() as u64 };
    // 150ms + (rand % 150ms)
    let jitter = (rand % 150) * 1_000_000;
    let base = 150 * 1_000_000;
    unsafe {
        ELECTION_DEADLINE_NS = now_ns + base + jitter;
    }
}

#[no_mangle]
pub extern "C" fn init(node_id: i32, cluster_size: i32) {
    unsafe {
        NODE_ID = node_id as u32;
        CLUSTER_SIZE = cluster_size as u32;
        CURRENT_TERM = 0;
        VOTED_FOR = 0;
        ROLE = ROLE_FOLLOWER;
        LOG_LEN = 0;
        COMMIT_INDEX = 0;
        LAST_APPLIED = 0;
        for i in 0..MAX_NODES {
            NEXT_INDEX[i] = 1;
            MATCH_INDEX[i] = 0;
        }
        for i in 0..MAX_KV {
            KV_STORE[i] = 0;
        }
        let now = crucible_virtual_time() as u64;
        reset_election_timeout(now);
        HEARTBEAT_DEADLINE_NS = now + 50 * 1_000_000;
    }
}

#[no_mangle]
pub extern "C" fn propose(key: i32, val: i32) -> i32 {
    unsafe {
        if ROLE != ROLE_LEADER {
            return -1; // Not leader
        }
        if LOG_LEN >= MAX_LOG {
            return -2;
        }
        let new_idx = (LOG_LEN + 1) as u32;
        LOG[LOG_LEN] = LogEntry {
            term: CURRENT_TERM,
            index: new_idx,
            key: key as u32,
            val: val as u32,
        };
        LOG_LEN += 1;
        MATCH_INDEX[NODE_ID as usize] = new_idx;
        broadcast_append_entries();
        new_idx as i32
    }
}

#[no_mangle]
pub extern "C" fn read(key: i32) -> i32 {
    unsafe {
        let k = key as usize;
        if k < MAX_KV {
            KV_STORE[k] as i32
        } else {
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn get_role() -> i32 {
    unsafe { ROLE as i32 }
}

#[no_mangle]
pub extern "C" fn get_term() -> i32 {
    unsafe { CURRENT_TERM as i32 }
}

#[no_mangle]
pub extern "C" fn get_commit_index() -> i32 {
    unsafe { COMMIT_INDEX as i32 }
}

#[no_mangle]
pub extern "C" fn get_log_len() -> i32 {
    unsafe { LOG_LEN as i32 }
}

unsafe fn broadcast_append_entries() {
    let mut packet = [0u8; 32];
    packet[0] = MSG_APPEND_ENTRIES;

    let term_bytes = CURRENT_TERM.to_le_bytes();
    packet[1..5].copy_from_slice(&term_bytes);

    let leader_bytes = NODE_ID.to_le_bytes();
    packet[5..9].copy_from_slice(&leader_bytes);

    let (prev_idx, prev_term, key, val) = if LOG_LEN > 0 {
        let last = LOG[LOG_LEN - 1];
        let p_idx = if LOG_LEN > 1 { LOG[LOG_LEN - 2].index } else { 0 };
        let p_term = if LOG_LEN > 1 { LOG[LOG_LEN - 2].term } else { 0 };
        (p_idx, p_term, last.key, last.val)
    } else {
        (0, 0, 0, 0)
    };

    packet[9..13].copy_from_slice(&prev_idx.to_le_bytes());
    packet[13..17].copy_from_slice(&prev_term.to_le_bytes());
    packet[17..21].copy_from_slice(&COMMIT_INDEX.to_le_bytes());
    packet[21..25].copy_from_slice(&key.to_le_bytes());
    packet[25..29].copy_from_slice(&val.to_le_bytes());
    let has_entry: u8 = if LOG_LEN > 0 { 1 } else { 0 };
    packet[29] = has_entry;

    for peer in 1..=CLUSTER_SIZE {
        if peer != NODE_ID {
            crucible_send_msg(peer as i32, packet.as_ptr() as i32, 30);
        }
    }
}

unsafe fn start_election(now_ns: u64) {
    ROLE = ROLE_CANDIDATE;
    CURRENT_TERM += 1;
    VOTED_FOR = NODE_ID;
    VOTES_GRANTED_MASK = 1 << NODE_ID;
    reset_election_timeout(now_ns);

    let last_log_idx = LOG_LEN as u32;
    let last_log_term = if LOG_LEN > 0 { LOG[LOG_LEN - 1].term } else { 0 };

    let mut packet = [0u8; 17];
    packet[0] = MSG_REQUEST_VOTE;
    packet[1..5].copy_from_slice(&CURRENT_TERM.to_le_bytes());
    packet[5..9].copy_from_slice(&NODE_ID.to_le_bytes());
    packet[9..13].copy_from_slice(&last_log_idx.to_le_bytes());
    packet[13..17].copy_from_slice(&last_log_term.to_le_bytes());

    for peer in 1..=CLUSTER_SIZE {
        if peer != NODE_ID {
            crucible_send_msg(peer as i32, packet.as_ptr() as i32, 17);
        }
    }
}

#[no_mangle]
pub extern "C" fn step() -> i32 {
    unsafe {
        let now = crucible_virtual_time() as u64;

        // 1. Check election timeout
        if ROLE != ROLE_LEADER && now >= ELECTION_DEADLINE_NS {
            start_election(now);
        }

        // 2. Leader heartbeat
        if ROLE == ROLE_LEADER && now >= HEARTBEAT_DEADLINE_NS {
            HEARTBEAT_DEADLINE_NS = now + 50 * 1_000_000;
            broadcast_append_entries();
        }

        // 3. Process all incoming messages
        let mut buf = [0u8; 64];
        let mut msgs_processed = 0;

        loop {
            let n = crucible_recv_msg(buf.as_mut_ptr() as i32, 64);
            if n <= 0 {
                break;
            }
            msgs_processed += 1;
            let msg_type = buf[0];

            match msg_type {
                MSG_REQUEST_VOTE => {
                    let term = read_u32(&buf, 1);
                    let candidate = read_u32(&buf, 5);
                    let last_idx = read_u32(&buf, 9);
                    let last_term = read_u32(&buf, 13);

                    if term > CURRENT_TERM {
                        CURRENT_TERM = term;
                        ROLE = ROLE_FOLLOWER;
                        VOTED_FOR = 0;
                    }

                    let mut vote_granted = false;
                    if term == CURRENT_TERM && (VOTED_FOR == 0 || VOTED_FOR == candidate) {
                        let my_last_idx = LOG_LEN as u32;
                        let my_last_term = if LOG_LEN > 0 { LOG[LOG_LEN - 1].term } else { 0 };
                        let up_to_date = last_term > my_last_term
                            || (last_term == my_last_term && last_idx >= my_last_idx);

                        if up_to_date {
                            vote_granted = true;
                            VOTED_FOR = candidate;
                            reset_election_timeout(now);
                        }
                    }

                    let mut reply = [0u8; 6];
                    reply[0] = MSG_REQUEST_VOTE_REPLY;
                    reply[1..5].copy_from_slice(&CURRENT_TERM.to_le_bytes());
                    reply[5] = if vote_granted { 1 } else { 0 };
                    crucible_send_msg(candidate as i32, reply.as_ptr() as i32, 6);
                }

                MSG_REQUEST_VOTE_REPLY => {
                    let term = read_u32(&buf, 1);
                    let granted = buf[5] == 1;

                    if term > CURRENT_TERM {
                        CURRENT_TERM = term;
                        ROLE = ROLE_FOLLOWER;
                        VOTED_FOR = 0;
                    } else if ROLE == ROLE_CANDIDATE && term == CURRENT_TERM && granted {
                        VOTES_GRANTED_MASK |= 1 << msgs_processed;
                        let mut count = 0;
                        for i in 1..=CLUSTER_SIZE {
                            if (VOTES_GRANTED_MASK & (1 << i)) != 0 {
                                count += 1;
                            }
                        }
                        if count > (CLUSTER_SIZE / 2) {
                            ROLE = ROLE_LEADER;
                            HEARTBEAT_DEADLINE_NS = now;
                            for i in 1..=CLUSTER_SIZE {
                                NEXT_INDEX[i as usize] = (LOG_LEN + 1) as u32;
                                MATCH_INDEX[i as usize] = 0;
                            }
                            MATCH_INDEX[NODE_ID as usize] = LOG_LEN as u32;
                            broadcast_append_entries();
                        }
                    }
                }

                MSG_APPEND_ENTRIES => {
                    let term = read_u32(&buf, 1);
                    let leader_id = read_u32(&buf, 5);
                    let _prev_idx = read_u32(&buf, 9);
                    let _prev_term = read_u32(&buf, 13);
                    let leader_commit = read_u32(&buf, 17);
                    let key = read_u32(&buf, 21);
                    let val = read_u32(&buf, 25);
                    let has_entry = buf[29] == 1;

                    if term > CURRENT_TERM {
                        CURRENT_TERM = term;
                        ROLE = ROLE_FOLLOWER;
                        VOTED_FOR = 0;
                    }

                    let mut success = false;
                    if term == CURRENT_TERM {
                        ROLE = ROLE_FOLLOWER;
                        reset_election_timeout(now);
                        success = true;

                        if has_entry && LOG_LEN < MAX_LOG {
                            let new_idx = (LOG_LEN + 1) as u32;
                            LOG[LOG_LEN] = LogEntry {
                                term,
                                index: new_idx,
                                key,
                                val,
                            };
                            LOG_LEN += 1;
                        }

                        if leader_commit > COMMIT_INDEX {
                            let max_match = LOG_LEN as u32;
                            COMMIT_INDEX = if leader_commit < max_match { leader_commit } else { max_match };
                        }
                    }

                    let mut reply = [0u8; 15];
                    reply[0] = MSG_APPEND_ENTRIES_REPLY;
                    reply[1..5].copy_from_slice(&CURRENT_TERM.to_le_bytes());
                    reply[5..9].copy_from_slice(&NODE_ID.to_le_bytes());
                    reply[9] = if success { 1 } else { 0 };
                    let match_idx = LOG_LEN as u32;
                    reply[10..14].copy_from_slice(&match_idx.to_le_bytes());
                    crucible_send_msg(leader_id as i32, reply.as_ptr() as i32, 15);
                }

                MSG_APPEND_ENTRIES_REPLY => {
                    let term = read_u32(&buf, 1);
                    let sender_id = read_u32(&buf, 5);
                    let success = buf[9] == 1;
                    let match_idx = read_u32(&buf, 10);

                    if term > CURRENT_TERM {
                        CURRENT_TERM = term;
                        ROLE = ROLE_FOLLOWER;
                        VOTED_FOR = 0;
                    } else if ROLE == ROLE_LEADER && term == CURRENT_TERM && success {
                        if (sender_id as usize) < MAX_NODES {
                            MATCH_INDEX[sender_id as usize] = match_idx;
                        }
                        if match_idx > COMMIT_INDEX {
                            let mut matches = 1; // leader itself
                            for i in 1..=CLUSTER_SIZE {
                                if i != NODE_ID && MATCH_INDEX[i as usize] >= match_idx {
                                    matches += 1;
                                }
                            }
                            if matches > (CLUSTER_SIZE / 2) {
                                COMMIT_INDEX = match_idx;
                                broadcast_append_entries();
                            }
                        }
                    }
                }

                _ => {}
            }
        }

        // 4. Apply committed entries to state machine
        while LAST_APPLIED < COMMIT_INDEX {
            let idx = LAST_APPLIED as usize;
            if idx < LOG_LEN {
                let entry = LOG[idx];
                let k = entry.key as usize;
                if k < MAX_KV {
                    KV_STORE[k] = entry.val;
                }
            }
            LAST_APPLIED += 1;
        }

        msgs_processed
    }
}
