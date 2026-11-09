use crucible_emu::run_elf_trace;
use std::fs;
use std::path::Path;

#[test]
fn test_spike1_musl_echo_determinism_1000_runs() {
    let elf_path = Path::new("../../tests/fixtures/musl_echo.elf");
    let fallback_path = Path::new("tests/fixtures/musl_echo.elf");
    let actual_path = if elf_path.exists() {
        elf_path
    } else if fallback_path.exists() {
        fallback_path
    } else {
        panic!("Fixture musl_echo.elf not found");
    };

    let elf_data = fs::read(actual_path).expect("Failed to read musl_echo.elf");

    println!("Running Spike 1: Testing musl TCP echo determinism across 1,000 runs...");

    // First run to establish baseline
    let (baseline_steps, baseline_hash) =
        run_elf_trace(&elf_data, 5_000_000).expect("Baseline run failed");

    println!(
        "Baseline completed: {} instructions stepped, trace hash: {:02x?}",
        baseline_steps, baseline_hash
    );

    assert!(baseline_steps > 0, "Execution stepped 0 instructions");

    // Run 1,000 consecutive runs and verify byte-identical trace hash
    for i in 1..=1000 {
        let (steps, hash) =
            run_elf_trace(&elf_data, 5_000_000).unwrap_or_else(|e| panic!("Run {} failed: {}", i, e));

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

        if i % 100 == 0 {
            println!("Verified {} / 1,000 runs...", i);
        }
    }

    println!("Spike 1 PASSED: 100% byte-identical determinism across 1,000 runs!");
}
