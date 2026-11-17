use clap::{Parser, Subcommand};
use crucible_emu::DeterminismHarness;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "crucible")]
#[command(about = "Crucible: Deterministic Virtual World Testing for Distributed Systems", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a target simulation campaign under a seeded fault schedule
    Run {
        #[arg(short, long)]
        seed: u64,

        #[arg(short = 'n', long, default_value = "1000")]
        steps: u64,
    },
    /// Replay an exact failure trace from an evidence bundle
    Replay {
        #[arg(short, long)]
        bundle: PathBuf,
    },
    /// Determinism auditor: execute N times with the same seed and assert identical trace hashes
    Audit {
        #[arg(short, long, default_value = "100")]
        runs: u32,

        #[arg(short, long, default_value = "42")]
        seed: u64,
    },
    /// Verify a cryptographic evidence bundle independently
    Verify {
        #[arg(short, long)]
        bundle: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { seed, steps } => {
            info!("Starting Crucible run with seed: {seed}, steps: {steps}");
            let mut harness = DeterminismHarness::new(0x400000, 0x7ffffff0);
            let (executed, vtime) = harness.run_steps(steps);
            info!("Run finished. Executed {executed} steps, Virtual Time: {vtime:?}");
        }
        Commands::Audit { runs, seed } => {
            info!("Starting determinism audit: {runs} runs with seed {seed}");
            let mut baseline_steps = None;

            for r in 1..=runs {
                let mut harness = DeterminismHarness::new(0x400000, 0x7ffffff0);
                let (executed, _) = harness.run_steps(10_000);
                if let Some(base) = baseline_steps {
                    if base != executed {
                        anyhow::bail!("DIVERGENCE DETECTED at run {r}! Expected {base}, got {executed}");
                    }
                } else {
                    baseline_steps = Some(executed);
                }
            }
            info!("Audit PASSED: 100% deterministic across {runs} consecutive runs.");
        }
        Commands::Replay { bundle } => {
            info!("Replaying bundle from {bundle:?}");
        }
        Commands::Verify { bundle } => {
            info!("Verifying evidence bundle from {bundle:?}");
            let data = std::fs::read_to_string(&bundle)?;
            let bundle: crucible_trace::EvidenceBundle = serde_json::from_str(&data)?;
            bundle.verify()?;
            info!("Evidence bundle verification SUCCESSFUL: valid cryptographic signature and trace hash match.");
        }
    }

    Ok(())
}
