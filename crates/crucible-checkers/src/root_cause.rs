//! Statistical Fault Localization and Root-Cause Ranking.
//!
//! Uses spectrum-based fault localization metrics (Ochiai, Tarantula) across
//! corpora of passing and failing campaign runs to isolate and rank the exact
//! root-cause fault schedule events.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// A recorded run from an exploration campaign with its fault set and pass/fail outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CampaignRun<T: Clone + Eq + std::hash::Hash> {
    pub run_id: u64,
    pub faults: HashSet<T>,
    pub failed: bool,
}

/// Suspicion ranking for an individual fault or event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuspectRanking<T: Clone> {
    pub fault: T,
    pub ochiai_score: f64,
    pub tarantula_score: f64,
    pub fail_count: usize,
    pub pass_count: usize,
    pub confidence: f64,
}

pub struct RootCauseRanker;

impl RootCauseRanker {
    /// Ranks suspect faults across a corpus of passing and failing runs.
    /// Returns rankings sorted in descending order of suspiciousness.
    pub fn rank_suspects<T>(runs: &[CampaignRun<T>]) -> Vec<SuspectRanking<T>>
    where
        T: Clone + Eq + std::hash::Hash,
    {
        let total_fail = runs.iter().filter(|r| r.failed).count();
        let total_pass = runs.iter().filter(|r| !r.failed).count();

        if total_fail == 0 {
            return Vec::new();
        }

        // Collect all distinct faults across all runs
        let mut fault_fail_counts: HashMap<T, usize> = HashMap::new();
        let mut fault_pass_counts: HashMap<T, usize> = HashMap::new();

        for run in runs {
            for fault in &run.faults {
                if run.failed {
                    *fault_fail_counts.entry(fault.clone()).or_insert(0) += 1;
                } else {
                    *fault_pass_counts.entry(fault.clone()).or_insert(0) += 1;
                }
            }
        }

        let mut rankings = Vec::new();
        let all_faults: HashSet<T> = fault_fail_counts.keys().chain(fault_pass_counts.keys()).cloned().collect();

        for fault in all_faults {
            let n_cf = fault_fail_counts.get(&fault).copied().unwrap_or(0);
            let n_cp = fault_pass_counts.get(&fault).copied().unwrap_or(0);

            // 1. Ochiai Metric: n_cf / sqrt(total_fail * (n_cf + n_cp))
            let ochiai = if total_fail > 0 && (n_cf + n_cp) > 0 {
                let denom = ((total_fail * (n_cf + n_cp)) as f64).sqrt();
                if denom > 0.0 {
                    n_cf as f64 / denom
                } else {
                    0.0
                }
            } else {
                0.0
            };

            // 2. Tarantula Metric: (n_cf / total_fail) / ((n_cf / total_fail) + (n_cp / total_pass))
            let tarantula = if total_fail > 0 && total_pass > 0 {
                let fail_ratio = n_cf as f64 / total_fail as f64;
                let pass_ratio = n_cp as f64 / total_pass as f64;
                let denom = fail_ratio + pass_ratio;
                if denom > 0.0 {
                    fail_ratio / denom
                } else {
                    0.0
                }
            } else if total_fail > 0 && n_cf > 0 {
                1.0
            } else {
                0.0
            };

            // Statistical confidence based on sample representation
            let confidence = (n_cf as f64 / total_fail as f64) * (1.0 - (n_cp as f64 / (n_cp + n_cf).max(1) as f64));

            rankings.push(SuspectRanking {
                fault,
                ochiai_score: ochiai,
                tarantula_score: tarantula,
                fail_count: n_cf,
                pass_count: n_cp,
                confidence,
            });
        }

        // Sort by Ochiai score descending, breaking ties with confidence
        rankings.sort_by(|a, b| {
            b.ochiai_score
                .partial_cmp(&a.ochiai_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal))
        });

        rankings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_cause_ranking_exact_culprit() {
        // Suppose BugFault is present in all 5 failing runs, and 0 passing runs.
        // NoiseFault is present in 3 failing runs and 5 passing runs.
        // BenignFault is present only in passing runs.
        let mut runs = Vec::new();

        // 5 failing runs
        for i in 1..=5 {
            let mut faults = HashSet::new();
            faults.insert("BugFault");
            if i % 2 == 0 {
                faults.insert("NoiseFault");
            }
            runs.push(CampaignRun {
                run_id: i,
                faults,
                failed: true,
            });
        }

        // 5 passing runs
        for i in 6..=10 {
            let mut faults = HashSet::new();
            faults.insert("BenignFault");
            faults.insert("NoiseFault");
            runs.push(CampaignRun {
                run_id: i,
                faults,
                failed: false,
            });
        }

        let rankings = RootCauseRanker::rank_suspects(&runs);

        assert!(!rankings.is_empty());
        // Rank 1 MUST be "BugFault"
        assert_eq!(rankings[0].fault, "BugFault");
        assert_eq!(rankings[0].ochiai_score, 1.0);
        assert_eq!(rankings[0].fail_count, 5);
        assert_eq!(rankings[0].pass_count, 0);

        // Rank 2 should be "NoiseFault" with significantly lower score
        assert_eq!(rankings[1].fault, "NoiseFault");
        assert!(rankings[1].ochiai_score < 1.0);
    }
}
