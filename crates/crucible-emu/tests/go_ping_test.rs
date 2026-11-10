use crucible_core::{SchedulingPolicy, Seed};
use crucible_emu::run_elf_trace_with_policy;
use std::fs;
use std::path::Path;

#[test]
fn test_spike2_go_ping_round_robin() {
    let elf_path = Path::new("../../tests/fixtures/go_ping.elf");
    let fallback_path = Path::new("tests/fixtures/go_ping.elf");
    let actual_path = if elf_path.exists() {
        elf_path
    } else if fallback_path.exists() {
        fallback_path
    } else {
        panic!("Fixture go_ping.elf not found");
    };

    let elf_data = fs::read(actual_path).expect("Failed to read go_ping.elf");

    println!("Testing Go runtime under RoundRobin scheduling policy...");
    let (steps, hash) = run_elf_trace_with_policy(
        &elf_data,
        5_000_000,
        SchedulingPolicy::RoundRobin,
        Seed(42),
    )
    .expect("RoundRobin execution failed");

    println!("RoundRobin completed: {} instructions, trace hash: {:02x?}", steps, hash);
    assert_eq!(steps, 336898);
}

#[test]
fn test_spike2_go_ping_crucible_adaptive() {
    let elf_path = Path::new("../../tests/fixtures/go_ping.elf");
    let fallback_path = Path::new("tests/fixtures/go_ping.elf");
    let actual_path = if elf_path.exists() {
        elf_path
    } else if fallback_path.exists() {
        fallback_path
    } else {
        panic!("Fixture go_ping.elf not found");
    };

    let elf_data = fs::read(actual_path).expect("Failed to read go_ping.elf");

    println!("Testing Go runtime under CrucibleAdaptive (Causal + Contention + PCT) scheduler...");
    let (steps, hash) = run_elf_trace_with_policy(
        &elf_data,
        10_000_000,
        SchedulingPolicy::CrucibleAdaptive {
            bug_depth: 3,
            base_quantum: 500,
            contention_quantum: 25,
        },
        Seed(42),
    )
    .expect("CrucibleAdaptive execution failed");

    println!("CrucibleAdaptive completed: {} instructions, trace hash: {:02x?}", steps, hash);
    assert_eq!(steps, 4884977);
}

#[test]
fn test_spike2_go_ping_reproducibility() {
    let elf_path = Path::new("../../tests/fixtures/go_ping.elf");
    let fallback_path = Path::new("tests/fixtures/go_ping.elf");
    let actual_path = if elf_path.exists() {
        elf_path
    } else if fallback_path.exists() {
        fallback_path
    } else {
        panic!("Fixture go_ping.elf not found");
    };

    let elf_data = fs::read(actual_path).expect("Failed to read go_ping.elf");

    // Verify bit-identical replay under CrucibleAdaptive across repeated executions
    let (run1_steps, run1_hash) = run_elf_trace_with_policy(
        &elf_data,
        10_000_000,
        SchedulingPolicy::CrucibleAdaptive {
            bug_depth: 3,
            base_quantum: 500,
            contention_quantum: 25,
        },
        Seed(42),
    )
    .expect("Run 1 failed");

    let (run2_steps, run2_hash) = run_elf_trace_with_policy(
        &elf_data,
        10_000_000,
        SchedulingPolicy::CrucibleAdaptive {
            bug_depth: 3,
            base_quantum: 500,
            contention_quantum: 25,
        },
        Seed(42),
    )
    .expect("Run 2 failed");

    assert_eq!(run1_steps, run2_steps);
    assert_eq!(run1_hash, run2_hash);
    println!("CrucibleAdaptive replay verified: 100% bit-exact across independent runs.");
}




