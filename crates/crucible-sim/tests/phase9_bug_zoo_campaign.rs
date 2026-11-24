//! Phase 9 Integration Test: 100-Node Bug Zoo Campaign Engine,
//! Automated Fault Minimization (<=5 events), and Cryptographic Evidence Export.

use crucible_sim::campaign::{CampaignFault, CampaignRunner, LargeDistributedCluster};
use crucible_trace::StandaloneVerifier;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

#[test]
fn test_100_node_cluster_large_scale_simulation() {
    let mut cluster = LargeDistributedCluster::new_100_node_cluster(None);
    assert_eq!(cluster.total_nodes, 100);
    assert_eq!(cluster.group_count, 20);

    // Initial elections across all 20 groups
    for g_idx in 0..20 {
        let first_node = (g_idx * 5 + 1) as u32;
        cluster.apply_fault(&CampaignFault::TriggerReconfiguration {
            group_idx: g_idx,
            candidate_id: first_node,
        });
    }

    // Advance 500 rounds (stepping all 100 nodes and delivering network traffic)
    let total_events = cluster.step_rounds(500);
    assert!(
        total_events > 0,
        "Cluster should execute substantial consensus steps, executed: {total_events}"
    );

    // Completely sound cluster must have zero safety violations
    let safety = cluster.check_safety();
    assert!(safety.is_ok(), "Sound 100-node cluster should have no safety violations");
}

#[test]
fn test_bug_zoo_split_brain_reproduction_and_minimization() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let runner = CampaignRunner::new(1337);
    let bug = runner
        .run_100_node_campaign(&signing_key)
        .expect("Campaign must successfully reproduce and minimize target bug");

    // 1. Verify initial vs minimized fault counts
    assert_eq!(bug.initial_fault_count, 10);
    assert!(
        bug.minimized_fault_count <= 5,
        "Delta debugging must reduce fault schedule to <= 5 events, got {}",
        bug.minimized_fault_count
    );
    assert_eq!(bug.minimized_fault_count, 3);

    // 2. Verify counterfactual fix
    assert!(
        bug.counterfactual_patch_verified,
        "Counterfactual verification must confirm patch eliminates bug"
    );

    // 3. Verify cryptographic evidence bundle
    let report = StandaloneVerifier::verify_static(&bug.evidence_bundle)
        .expect("Static verification must succeed");
    assert!(report.signature_valid, "Ed25519 signature must be mathematically valid");
    assert!(report.merkle_root_valid, "RFC 6962 Merkle root must match all events");

    // 4. Verify markdown bug report generation
    let report_md = bug.to_markdown_report();
    assert!(report_md.contains("CRUCIBLE SECURITY ADVISORY / UPSTREAM BUG REPORT"));
    assert!(report_md.contains("Split-brain safety violation in Group 7"));
    assert!(report_md.contains("Counterfactual Verification"));
    assert!(report_md.contains(&bug.evidence_bundle.merkle_root));
}

#[test]
fn test_counterfactual_validation_isolated() {
    // Sound cluster on same schedule should never violate safety
    let mut sound_cluster = LargeDistributedCluster::new_100_node_cluster(None);
    let target_buggy_group = 7;
    let g7_start = (target_buggy_group * 5 + 1) as u32;

    let faults = vec![
        CampaignFault::TriggerReconfiguration {
            group_idx: target_buggy_group,
            candidate_id: g7_start,
        },
        CampaignFault::IsolateGroup {
            group_idx: target_buggy_group,
            isolated_nodes: vec![g7_start, g7_start + 1],
        },
        CampaignFault::TriggerReconfiguration {
            group_idx: target_buggy_group,
            candidate_id: g7_start + 4,
        },
    ];

    for fault in faults {
        sound_cluster.apply_fault(&fault);
        sound_cluster.step_rounds(10);
    }

    assert!(
        sound_cluster.check_safety().is_ok(),
        "Sound cluster must not violate safety under joint consensus transition faults"
    );
}
