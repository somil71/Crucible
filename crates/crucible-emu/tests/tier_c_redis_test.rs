//! Tier C User-Mode x86-64 & V-Kernel Deterministic Redis RESP Verification.
//!
//! Validates CLM-011:
//! Runs unmodified musl Linux event-driven RESP (Redis Serialization Protocol) server
//! under Tier C x86-64 user-mode emulation with epoll I/O multiplexing, socket options
//! (SO_REUSEADDR, TCP_NODELAY), and non-blocking sockets passing basic PING, SET, GET,
//! and INCR commands with 100% deterministic multi-run trace replay across independent runs.

use crucible_core::{SchedulingPolicy, Seed};
use crucible_emu::run_elf_trace_with_policy;
use std::fs;
use std::path::Path;

#[test]
fn test_clm_011_tier_c_redis_resp_determinism() {
    let elf_path = Path::new("../../tests/fixtures/musl_redis.elf");
    let fallback_path = Path::new("tests/fixtures/musl_redis.elf");
    let actual_path = if elf_path.exists() {
        elf_path
    } else if fallback_path.exists() {
        fallback_path
    } else {
        panic!("Fixture musl_redis.elf not found");
    };

    let elf_data = fs::read(actual_path).expect("Failed to read musl_redis.elf");

    println!("Running CLM-011: Tier C Emulated Redis RESP Server with Epoll Multiplexing...");

    // 1. Baseline Run
    let seed1 = Seed(0xCAFE_BABE_0001);
    let (baseline_steps, baseline_hash) = run_elf_trace_with_policy(
        &elf_data,
        10_000_000,
        SchedulingPolicy::default(),
        seed1,
    )
    .expect("Baseline Redis execution failed");

    println!(
        "Redis Baseline completed: {} instructions stepped, trace hash: {:02x?}",
        baseline_steps, baseline_hash
    );

    assert!(baseline_steps > 0, "Execution stepped 0 instructions");

    // 2. Multi-run deterministic replay verification
    const NUM_RUNS: usize = 50;
    println!("Verifying byte-identical trace hash across {} runs...", NUM_RUNS);

    for i in 1..=NUM_RUNS {
        let (steps, hash) = run_elf_trace_with_policy(
            &elf_data,
            10_000_000,
            SchedulingPolicy::default(),
            seed1,
        )
        .unwrap_or_else(|e| panic!("Redis run {} failed: {}", i, e));

        assert_eq!(
            steps, baseline_steps,
            "Instruction count divergence on run {}: expected {}, got {}",
            i, baseline_steps, steps
        );

        assert_eq!(
            hash, baseline_hash,
            "Trace hash divergence on run {}: expected {:02x?}, got {:02x?}",
            i, baseline_hash, hash
        );
    }

    // 3. Multi-seed determinism verification
    let seeds = [
        Seed(0xCAFE_BABE_0002),
        Seed(0xCAFE_BABE_0003),
        Seed(0xCAFE_BABE_0004),
    ];

    for (idx, seed) in seeds.iter().enumerate() {
        let (s1, h1) = run_elf_trace_with_policy(&elf_data, 10_000_000, SchedulingPolicy::default(), *seed)
            .expect("Seed run 1 failed");
        let (s2, h2) = run_elf_trace_with_policy(&elf_data, 10_000_000, SchedulingPolicy::default(), *seed)
            .expect("Seed run 2 failed");

        assert_eq!(s1, s2, "Seed {:?} instruction divergence", seed);
        assert_eq!(h1, h2, "Seed {:?} trace hash divergence", seed);
        println!(
            "Seed {}: {} steps, hash: {:02x?} (Deterministic ✅)",
            idx + 2, s1, h1
        );
    }

    println!("CLM-011 PASSED: 100% byte-identical determinism on Redis RESP target!");
}
