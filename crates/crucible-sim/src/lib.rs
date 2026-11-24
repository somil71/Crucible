//! Crucible Sim - Tier A In-Memory Distributed Simulator and Search Engine.

pub mod campaign;
pub mod network;
pub mod raft;
pub mod raft_history;
pub mod search;
pub mod storage;
pub mod virtual_engine;

pub use campaign::{CampaignFault, CampaignRunner, DiscoveredBug, LargeDistributedCluster};
pub use network::{NetworkPacket, SimulatedNetwork};
pub use raft::{ClusterConfig, LogEntry, RaftMessage, RaftNode, Role};
pub use raft_history::{
    execute_history_schedule, HistoricalEntry, HistoricalRaftCluster, HistoricalRaftNode,
    HistoryFault, HistoryRole,
};
pub use search::{
    ClusterAction, ClusterStateDigest, CoverageGuidedExplorer, RaftCluster, SafetyViolation,
    UniformRandomScheduler,
};
pub use storage::{CrashFault, SimulatedBlockStore, StorageError, SECTOR_SIZE};
pub use virtual_engine::{JumpBenchmarkReport, ScheduledClusterEvent, VirtualWorldEngine};
use crucible_core::Seed;

/// Runs a single search trial under a given scheduler up to `max_steps`.
/// Returns Ok(steps_to_bug) if a violation was found, or Err("No violation") if max_steps reached.
pub fn run_uniform_random_trial(seed: Seed, max_steps: usize) -> Result<usize, String> {
    let mut cluster = RaftCluster::new_joint_cluster(true); // seeded split-brain bug enabled
    let mut scheduler = UniformRandomScheduler::new(seed);

    for step in 1..=max_steps {
        let action = scheduler.pick_action();
        cluster.step_action(action);

        if cluster.check_safety().is_err() {
            return Ok(step);
        }
    }

    Err("No violation within step limit".into())
}

/// Runs a single search trial under the coverage-guided bandit explorer up to `max_steps`.
/// Returns Ok(steps_to_bug) if a violation was found, or Err("No violation") if max_steps reached.
pub fn run_coverage_guided_trial(seed: Seed, max_steps: usize) -> Result<usize, String> {
    let mut cluster = RaftCluster::new_joint_cluster(true); // seeded split-brain bug enabled
    let mut explorer = CoverageGuidedExplorer::new(seed);

    for step in 1..=max_steps {
        let digest = cluster.state_digest();
        explorer.update_feedback(&digest);

        let action = explorer.pick_action(&cluster);
        cluster.step_action(action);

        if cluster.check_safety().is_err() {
            return Ok(step);
        }
    }

    Err("No violation within step limit".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_toy_raft_joint_consensus_split_brain_triggered() {
        let mut cluster = RaftCluster::new_joint_cluster(true);
        let n1 = crucible_core::NodeId(1);
        let n2 = crucible_core::NodeId(2);
        let n3 = crucible_core::NodeId(3);
        let n4 = crucible_core::NodeId(4);

        // Partition C_old {1, 2} from C_new {3, 4}
        cluster.step_action(ClusterAction::Partition(vec![n1, n2], vec![n3, n4]));

        // N1 triggers election in C_old {1, 2}
        cluster.step_action(ClusterAction::TriggerElection(n1));
        for _ in 0..10 {
            cluster.step_action(ClusterAction::DeliverPacket);
        }

        // N3 triggers election in C_new {3, 4}
        cluster.step_action(ClusterAction::TriggerElection(n3));
        for _ in 0..10 {
            cluster.step_action(ClusterAction::DeliverPacket);
        }

        // Both nodes became leader under flawed joint consensus checking!
        let violation = cluster.check_safety();
        assert!(violation.is_err(), "Seeded joint consensus bug must produce a safety violation");
    }
}
