//! Spike 3: Search Efficiency Benchmark - Coverage-Guided Bandit vs. Uniform Random Baseline.
//! Verifies Claim CLM-003: Coverage-guided fault scheduling discovers safety violations
//! with at least 3x fewer iterations compared to uniform random scheduling.

use crucible_core::Seed;
use crucible_sim::{run_coverage_guided_trial, run_uniform_random_trial};

#[test]
fn test_spike3_coverage_vs_random_benchmark() {
    const NUM_TRIALS: usize = 100;
    const MAX_STEPS: usize = 2_000;

    let mut random_iterations = Vec::with_capacity(NUM_TRIALS);
    let mut coverage_iterations = Vec::with_capacity(NUM_TRIALS);

    println!("Running Spike 3 Benchmark across {} independent seed trials...", NUM_TRIALS);

    for trial in 1..=NUM_TRIALS {
        let seed = Seed((trial * 7919) as u64);

        // Run uniform random baseline
        let rand_steps = run_uniform_random_trial(seed, MAX_STEPS)
            .unwrap_or(MAX_STEPS); // Cap at MAX_STEPS if not found
        random_iterations.push(rand_steps);

        // Run coverage-guided bandit explorer
        let cov_steps = run_coverage_guided_trial(seed, MAX_STEPS)
            .unwrap_or(MAX_STEPS);
        coverage_iterations.push(cov_steps);
    }

    let avg_random: f64 = random_iterations.iter().sum::<usize>() as f64 / NUM_TRIALS as f64;
    let avg_coverage: f64 = coverage_iterations.iter().sum::<usize>() as f64 / NUM_TRIALS as f64;
    let speedup = avg_random / avg_coverage;

    println!("============================================================");
    println!("SPIKE 3 STATISTICAL RESULTS (N = {} trials):", NUM_TRIALS);
    println!("  Uniform Random Mean Iterations: {:.2}", avg_random);
    println!("  Coverage-Guided Mean Iterations: {:.2}", avg_coverage);
    println!("  Empirical Speedup Factor: {:.2}x", speedup);
    println!("============================================================");

    // Assert strictly >= 3x search advantage as specified in Master Roadmap kill-gate
    assert!(
        speedup >= 3.0,
        "Coverage-guided explorer must achieve >= 3.0x speedup over uniform random (got {:.2}x)",
        speedup
    );

    // Verify coverage-guided explorer found the bug in 100% of trials
    let coverage_success_count = coverage_iterations.iter().filter(|&&s| s < MAX_STEPS).count();
    assert_eq!(
        coverage_success_count, NUM_TRIALS,
        "Coverage-guided explorer should reliably locate the bug on all trials"
    );
}
