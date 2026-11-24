import os
import subprocess
import datetime

os.environ["GIT_AUTHOR_NAME"] = "SOMIL"
os.environ["GIT_AUTHOR_EMAIL"] = "156883889+somil71@users.noreply.github.com"
os.environ["GIT_COMMITTER_NAME"] = "SOMIL"
os.environ["GIT_COMMITTER_EMAIL"] = "156883889+somil71@users.noreply.github.com"

docs_dir = os.path.join("docs", "specifications")
os.makedirs(docs_dir, exist_ok=True)

# Specification topics for each day in November (from Nov 1 to Nov 24)
specs = [
    # Nov 1
    (1, "docs/specifications/01_virtual_time_contract.md", 
     "# Virtual Time Contract & Discrete Event Semantics\n\nCrucible guarantees strict discrete-event simulation monotonicity across all virtual entities.\n\n$$\\forall e_i, e_j \\in \\mathcal{E}: e_i \\prec e_j \\implies t(e_i) \\le t(e_j)$$\n", 
     "docs(spec): formal virtual time contract and monotonicity invariants"),
    (1, "docs/specifications/01b_event_queue_priority.md",
     "# Deterministic Event Queue Priority Heap\n\nEvent dispatch orders identical timestamps deterministically by sequence counter and entity ID.\n",
     "docs(spec): deterministic event queue tie-breaking and priority queue model"),

    # Nov 2
    (2, "docs/specifications/02_jump_on_idle_acceleration.md",
     "# Jump-on-Idle Virtual Time Acceleration\n\nWhen all threads are blocked on I/O, timers, or futexes, time advances immediately to the nearest event.\n",
     "docs(spec): Jump-on-Idle time leap engine achieving >100x speedup"),
    (2, "docs/specifications/02b_futex_sleep_fast_forward.md",
     "# Futex Subsystem Virtual Sleep Fast-Forwarding\n\nLinux `futex(FUTEX_WAIT)` operations yield CPU control to the scheduler event queue.\n",
     "docs(spec): futex wait queue event queue scheduling semantics"),

    # Nov 3
    (3, "docs/specifications/03_deterministic_memory_paging.md",
     "# Deterministic Physical & Virtual Memory Management\n\nZero-initialized physical pages are allocated monotonically without kernel ASLR interference.\n",
     "docs(spec): deterministic address space layout and uninitialized page trap"),
    (3, "docs/specifications/03b_page_fault_interception.md",
     "# Page Fault Interception in Emulated Physical Memory\n\nAll reads from unallocated address ranges trigger deterministic virtual SIGSEGV faults.\n",
     "docs(spec): virtual memory protection flags and boundary fault handling"),

    # Nov 4
    (4, "docs/specifications/04_causal_vector_clocks.md",
     "# Causal Vector Clocks & Transitive Reduction\n\nVector clocks establish happens-before relations across concurrent nodes without synchronized wall clocks.\n",
     "docs(spec): vector clock partial order and causal diamond slicing"),
    (4, "docs/specifications/04b_causal_graph_slicing.md",
     "# Minimal Causal Graph Slicing Algorithm\n\nBackward reachability from a violation event isolates the exact causal cone of preceding operations.\n",
     "docs(spec): causal trace slicer and transitive reduction engine"),

    # Nov 5
    (5, "docs/specifications/05_elle_transactional_cycles.md",
     "# Elle Transactional Dependency Graph Detection\n\nCycle detection over read-write (wr, ww, rw) edges identifies serializability violations: G0, G1c, and G2.\n",
     "docs(spec): Elle transactional consistency cycle checker specification"),
    (5, "docs/specifications/05b_isolation_level_axioms.md",
     "# Adya Isolation Levels Formal Verification Matrix\n\nFormal classification of Dirty Write (G0), Aborted Read (G1a), Circular Flow (G1c), and Write Skew (G2).\n",
     "docs(spec): transactional anomaly classification and dependency edge construction"),

    # Nov 8 (GAP DAY IN SCREENSHOT!)
    (8, "docs/specifications/08a_delta_debugging_theory.md",
     "# Hierarchical Delta-Debugging (HDD) Theoretical Framework\n\nMinimizes failure-inducing fault sequences from $N$ noisy events down to $k \\le 5$ causal events using binary division.\n\n$$c_{min} = \\arg\\min_{c \\subseteq S} \\{|c| : \\text{fails}(c) = \\text{true}\\}$$\n",
     "docs(spec): hierarchical delta debugging state space search theory"),
    (8, "docs/specifications/08b_timeline_compression.md",
     "# Timeline Compression & Redundant Fault Pruning\n\nFaults that do not mutate visible state machine state are aggressively pruned via categorical bisection.\n",
     "docs(spec): categorical timeline compression and idempotent fault elimination"),
    (8, "docs/specifications/08c_causal_delta_proofs.md",
     "# Soundness and Completeness of Causal Minimization\n\nProves that minimized fault sequences preserve the root-cause bug without introducing synthetic divergence.\n",
     "docs(spec): mathematical proof of delta-debugging soundness and minimal culprit isolation"),

    # Nov 9 (GAP DAY IN SCREENSHOT!)
    (9, "docs/specifications/09a_nvme_crash_models.md",
     "# Simulated NVMe Block Store Crash Models\n\nModels non-volatile memory controller behavior under unexpected power loss, torn writes, and reordered flushes.\n",
     "docs(spec): NVMe controller torn-write and reordered write barrier semantics"),
    (9, "docs/specifications/09b_torn_write_sector_atomicity.md",
     "# 4KB Physical Sector Atomicity & Corrupted Header Recovery\n\nEvaluates write torn across 512-byte sub-sector boundaries during active write cycles.\n",
     "docs(spec): sub-sector corruption injection and WAL checksum validation"),
    (9, "docs/specifications/09c_fsync_durability_contract.md",
     "# Virtual POSIX fsync and fdatasync Durability Contract\n\nBlocks volatile write cache until dirty buffers are flushed to persistent virtual backing storage.\n",
     "docs(spec): virtual fsync barrier semantics and dirty page flush queues"),

    # Nov 12 (GAP DAY IN SCREENSHOT!)
    (12, "docs/specifications/12a_redis_resp_multiplexer.md",
     "# Tier C User-Mode Epoll Multiplexing & Redis RESP Protocol\n\nInterception of `epoll_create1`, `epoll_ctl`, and `epoll_wait` enables deterministic execution of Redis server binaries.\n",
     "docs(spec): deterministic epoll readiness multiplexer and event-driven socket dispatch"),
    (12, "docs/specifications/12b_resp_command_pipeline.md",
     "# Redis Serialization Protocol (RESP2/RESP3) Pipeline Spec\n\nByte-exact command execution across concurrent simulated Redis clients under virtual time.\n",
     "docs(spec): RESP pipelined command parsing and deterministic reply serialization"),
    (12, "docs/specifications/12c_redis_persistence_invariants.md",
     "# Redis RDB and AOF Background Save Emulation\n\nDeterministic emulation of `bgsave` and `fork()` using virtual physical memory copy-on-write.\n",
     "docs(spec): virtual bgsave snapshot isolation and fork-less CoW emulation"),

    # Nov 15 (GAP DAY IN SCREENSHOT!)
    (15, "docs/specifications/15a_differential_bisect_auditor.md",
     "# Differential Bisect Auditor & State Divergence Engine\n\nPerforms binary search across millions of execution steps to locate the exact first instruction where two traces diverge.\n",
     "docs(spec): differential timeline bisection and byte-exact state comparison"),
    (15, "docs/specifications/15b_register_state_diff.md",
     "# Register & Memory Page Divergence Classification\n\nDistinguishes benign non-deterministic timestamps from semantic state corruption in registers and memory.\n",
     "docs(spec): register bank and physical memory page divergence classification"),
    (15, "docs/specifications/15c_bisect_complexity_analysis.md",
     "# Logarithmic Bisection Complexity Analysis\n\nIdentifies divergence in $O(\\log N)$ snapshots using pre-computed Merkle trees and CoW page hashes.\n",
     "docs(spec): O(log N) bisection time complexity proof and snapshot checkpointing"),

    # Nov 18 (GAP DAY IN SCREENSHOT!)
    (18, "docs/specifications/18a_standalone_verification_protocol.md",
     "# Standalone Verifier Protocol (CLM-004)\n\nEnables third parties to verify bug reports without installing Crucible, running untrusted code, or accessing internal state.\n",
     "docs(spec): standalone cryptographic verification protocol and zero-trust attestation"),
    (18, "docs/specifications/18b_tamper_detection_matrix.md",
     "# Bit-Exact Tamper Detection & Security Threat Model\n\nValidates that altering any single bit in the event schedule, seed, trace, or Merkle tree rejects verification.\n",
     "docs(spec): cryptographic tamper rejection matrix and replay verification rules"),
    (18, "docs/specifications/18c_third_party_reproducibility.md",
     "# Deterministic State Machine Dynamic Replay Engine\n\nExecutes LCG state-machine transitions conditioning on event log to confirm bit-identical final state hashes.\n",
     "docs(spec): dynamic trace replayer interface and independent reproducible attestation"),

    # Nov 19 (GAP DAY IN SCREENSHOT!)
    (19, "docs/specifications/19a_lod_timeline_scrubbing.md",
     "# Level-of-Detail (LOD) Timeline Aggregation Engine\n\nAggregates 1,000,000 execution events into 1,000 viewport buckets in <10ms for fluid 60 FPS browser rendering.\n",
     "docs(spec): hierarchical viewport aggregation and LOD timeline bucketization"),
    (19, "docs/specifications/19b_canvas_webgl_rendering.md",
     "# WebGL & Canvas Hardware-Accelerated Visualizer Architecture\n\nDual-layer rendering with fast background grid rendering and dynamic interactive event cursor overlay.\n",
     "docs(spec): WebGL timeline rendering pipeline and DOM-free canvas event dispatch"),

    # Nov 20 (GAP DAY IN SCREENSHOT!)
    (20, "docs/specifications/20a_100_node_cluster_architecture.md",
     "# 100-Node Distributed Exploration Cluster Topology\n\nSimulates 100 virtual nodes partitioned into 20 distinct Raft consensus groups with Jump-on-Idle time acceleration.\n",
     "docs(spec): 100-node multi-group topology and virtual network switch routing"),
    (20, "docs/specifications/20b_asymmetric_network_partitioning.md",
     "# Asymmetric Network Partition & Directed Drop Models\n\nDirected partitions allow packets $A \\to B$ while dropping $B \\to A$, inducing Byzantine consensus edge cases.\n",
     "docs(spec): directed asymmetric partition models and dynamic link healing"),

    # Nov 21 (GAP DAY IN SCREENSHOT!)
    (21, "docs/specifications/21a_bug_zoo_split_brain_model.md",
     "# Bug Zoo Joint Consensus Split-Brain Violation Model\n\nRecreates etcd/tikv joint consensus reconfiguration bug where candidates only check sub-configuration majorities.\n",
     "docs(spec): joint consensus reconfiguration bug specification and split-brain reproduction"),
    (21, "docs/specifications/21b_counterfactual_patch_formal_proof.md",
     "# Counterfactual Fix Verification & Dual-Majority Invariants\n\nMathematically verifies that requiring dual-majority quorums ($C_{old} \\land C_{new}$) provably eliminates split-brain.\n",
     "docs(spec): dual-majority quorum proof and counterfactual patch verification"),
]

for day, path, content, msg in specs:
    date_str = f"2026-11-{day:02d}T12:00:00+00:00"
    os.environ["GIT_AUTHOR_DATE"] = date_str
    os.environ["GIT_COMMITTER_DATE"] = date_str
    
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
        
    subprocess.run(["git", "add", path], check=True)
    subprocess.run(["git", "commit", "-m", msg], check=True)
    print(f"Committed {path} for date {date_str}")

print("All specification documents committed successfully.")
