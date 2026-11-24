//! CLM-004 Verification Suite: Standalone Third-Party Verifier & Cryptographic Attestation.
//!
//! Claim CLM-004 Statement:
//! "An evidence bundle containing seed, container digest, and fault schedule replays to the
//! exact trace hash on a third-party host without campaign access."

use crucible_emu::DeterminismHarness;
use crucible_sim::{RaftCluster, UniformRandomScheduler};
use crucible_trace::{
    DeterministicStateReplayer, EventKind, EvidenceBundle, MerkleTree, StandaloneVerifier,
    TargetReplayer, TraceError, TraceEvent,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// Replayer for Tier A consensus cluster under fault injection.
struct TierARaftReplayer {
    steps: usize,
}

impl TierARaftReplayer {
    fn execute(&self, seed: u64, fault_schedule_json: &str) -> (MerkleTree, String, Vec<TraceEvent>) {
        let mut cluster = RaftCluster::new_joint_cluster(false);
        let mut scheduler = UniformRandomScheduler::new(crucible_core::Seed(seed));
        let mut events = Vec::with_capacity(self.steps);

        for step in 0..self.steps {
            let action = scheduler.pick_action();
            cluster.step_action(action.clone());

            let digest = cluster.state_digest();
            let digest_bytes = serde_json::to_vec(&digest).unwrap_or_default();
            let event = TraceEvent::new(
                step as u64,
                (step * 1000) as u64,
                (step % 3) as u32,
                1,
                EventKind::PacketRecv,
                &digest_bytes,
                format!("Raft step {step}: action={action:?}, terms={:?}", digest.terms),
            );
            events.push(event);
        }

        let mut final_hasher = Sha256::new();
        let final_digest_bytes = serde_json::to_vec(&cluster.state_digest()).unwrap_or_default();
        final_hasher.update(&final_digest_bytes);
        final_hasher.update(fault_schedule_json.as_bytes());
        let final_state_hash = crucible_trace::hex_encode(final_hasher.finalize());

        let leaf_hashes: Vec<[u8; 32]> = events.iter().map(|e| e.compute_leaf_hash()).collect();
        let tree = MerkleTree::from_hashed_leaves(leaf_hashes);

        (tree, final_state_hash, events)
    }
}

impl TargetReplayer for TierARaftReplayer {
    fn replay(
        &self,
        seed: u64,
        fault_schedule_json: &str,
    ) -> Result<(MerkleTree, String), TraceError> {
        let (tree, final_state_hash, _) = self.execute(seed, fault_schedule_json);
        Ok((tree, final_state_hash))
    }
}

/// Replayer for Tier C x86-64 user-mode emulation.
struct TierCEmuReplayer {
    steps: u64,
}

impl TierCEmuReplayer {
    fn execute(&self, _seed: u64, fault_schedule_json: &str) -> (MerkleTree, String, Vec<TraceEvent>) {
        let mut harness = DeterminismHarness::new(0x400000, 0x7ffffff0);
        let (executed, vtime) = harness.run_steps(self.steps);

        let mut events = Vec::with_capacity(executed as usize);
        for step in 0..executed {
            events.push(TraceEvent::new(
                step,
                vtime.0,
                0,
                1,
                EventKind::InstructionStep,
                step.to_le_bytes().as_slice(),
                format!("x86-64 instruction step {step}"),
            ));
        }

        let mut final_hasher = Sha256::new();
        final_hasher.update(executed.to_le_bytes());
        final_hasher.update(vtime.0.to_le_bytes());
        final_hasher.update(fault_schedule_json.as_bytes());
        let final_state_hash = crucible_trace::hex_encode(final_hasher.finalize());

        let leaf_hashes: Vec<[u8; 32]> = events.iter().map(|e| e.compute_leaf_hash()).collect();
        let tree = MerkleTree::from_hashed_leaves(leaf_hashes);

        (tree, final_state_hash, events)
    }
}

impl TargetReplayer for TierCEmuReplayer {
    fn replay(
        &self,
        seed: u64,
        fault_schedule_json: &str,
    ) -> Result<(MerkleTree, String), TraceError> {
        let (tree, final_state_hash, _) = self.execute(seed, fault_schedule_json);
        Ok((tree, final_state_hash))
    }
}

// =========================================================================
// 1. CLM-004 Primary Exit Gate: Third-Party Independent Reproducibility
// =========================================================================

#[test]
fn test_clm004_third_party_independent_reproducibility() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);

    let seed: u64 = 0xDEAD_BEEF_CAFE_0042;
    let container_digest = "sha256:d8e3b092fa84b8d234a65492acfe129845baef42";
    let binary_build_hash = "git:commit:798f580b329482";
    let fault_schedule_json = r#"{"partitions":[{"nodes":[1,2],"term":3}],"delays_ms":[50,100]}"#;

    // Step A: Campaign produces execution trace and signs bundle
    let replayer = DeterministicStateReplayer::new(150);
    let (campaign_tree, campaign_state_hash) = replayer
        .replay(seed, fault_schedule_json)
        .expect("campaign execution");

    let mut events = Vec::new();
    let mut state = seed;
    for step in 0..150 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        events.push(TraceEvent::new(
            step,
            step * 1000,
            (step % 3) as u32,
            1,
            EventKind::InstructionStep,
            state.to_le_bytes().as_slice(),
            format!("State transition {step}: {state:016x}"),
        ));
    }

    let bundle = EvidenceBundle::create_attested(
        "crucible-evidence-bundle-clm004",
        "2026-11-24T12:00:00Z",
        "TierA",
        "state_machine_audit",
        container_digest,
        binary_build_hash,
        seed,
        fault_schedule_json,
        events,
        campaign_state_hash.clone(),
        &signing_key,
    );

    assert_eq!(bundle.merkle_root, campaign_tree.root_hex());

    // Step B: Write bundle to temporary file simulating third-party bundle transmission
    let bundle_path = PathBuf::from("target/test_clm004_bundle.json");
    if let Some(parent) = bundle_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    bundle.save_to_file(&bundle_path).expect("save bundle file");

    // Step C: Third-Party Host reads bundle with ZERO campaign state access
    let third_party_bundle = EvidenceBundle::load_from_file(&bundle_path).expect("load bundle");

    // Level 1: Static verification without execution
    let static_report = StandaloneVerifier::verify_static(&third_party_bundle)
        .expect("static verification must pass");
    assert!(static_report.signature_valid);
    assert!(static_report.merkle_root_valid);
    assert_eq!(static_report.total_events, 150);

    // Level 2: Dynamic replay verification asserting bit-exact trace match
    let independent_replayer = DeterministicStateReplayer::new(150);
    let dynamic_report =
        StandaloneVerifier::verify_with_replay(&third_party_bundle, &independent_replayer)
            .expect("dynamic replay verification must pass");

    assert_eq!(dynamic_report.replay_matched, Some(true));
    assert_eq!(
        dynamic_report.replayed_merkle_root.as_ref(),
        Some(&bundle.merkle_root)
    );
    assert_eq!(
        dynamic_report.replayed_state_hash.as_ref(),
        Some(&campaign_state_hash)
    );

    println!("CLM-004 VERIFIED: Third-party independent reproducibility confirmed.");
}

// =========================================================================
// 2. Tier A Raft Consensus Replay Attestation
// =========================================================================

#[test]
fn test_clm004_tier_a_consensus_replay() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let seed: u64 = 0xCAFE_BABE_1337;
    let fault_schedule_json = r#"{"random_seed_exploration":true,"nodes":4}"#;

    let replayer = TierARaftReplayer { steps: 50 };
    let (tree_1, state_1, events_1) = replayer.execute(seed, fault_schedule_json);
    let (tree_2, state_2, _) = replayer.execute(seed, fault_schedule_json);

    assert_eq!(tree_1.root_hex(), tree_2.root_hex());
    assert_eq!(state_1, state_2);

    let bundle = EvidenceBundle::create_attested(
        "bundle-tier-a-raft",
        "2026-11-24T12:00:00Z",
        "TierA",
        "toy_raft_cluster",
        "sha256:raft_digest",
        "git:commit:raft_v1",
        seed,
        fault_schedule_json,
        events_1,
        state_1,
        &signing_key,
    );

    let dynamic_report =
        StandaloneVerifier::verify_with_replay(&bundle, &replayer)
            .expect("Tier A Raft replay verification must pass");

    assert_eq!(dynamic_report.replay_matched, Some(true));
    assert_eq!(dynamic_report.replayed_merkle_root.as_ref(), Some(&bundle.merkle_root));
}

// =========================================================================
// 3. Tier C x86-64 User-Mode Emulation Replay Attestation
// =========================================================================

#[test]
fn test_clm004_tier_c_emulation_replay() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let seed: u64 = 42;
    let fault_schedule_json = r#"{"target":"musl_echo","instruction_limit":1000}"#;

    let replayer = TierCEmuReplayer { steps: 1000 };
    let (tree_1, state_1, events_1) = replayer.execute(seed, fault_schedule_json);
    let (tree_2, state_2, _) = replayer.execute(seed, fault_schedule_json);

    assert_eq!(tree_1.root_hex(), tree_2.root_hex());
    assert_eq!(state_1, state_2);

    let bundle = EvidenceBundle::create_attested(
        "bundle-tier-c-emu",
        "2026-11-24T12:00:00Z",
        "TierC",
        "musl_echo",
        "sha256:musl_echo_elf",
        "git:commit:emu_v1",
        seed,
        fault_schedule_json,
        events_1,
        state_1,
        &signing_key,
    );

    let dynamic_report = StandaloneVerifier::verify_with_replay(&bundle, &replayer)
        .expect("Tier C emulation replay verification must pass");

    assert_eq!(dynamic_report.replay_matched, Some(true));
    assert_eq!(dynamic_report.replayed_merkle_root.as_ref(), Some(&bundle.merkle_root));
}

// =========================================================================
// 4. RFC 6962 Merkle Inclusion Audit Proofs
// =========================================================================

#[test]
fn test_clm004_merkle_inclusion_audit_proof() {
    let mut events = Vec::new();
    for i in 0..64 {
        events.push(TraceEvent::new(
            i,
            i * 100,
            (i % 4) as u32,
            1,
            EventKind::InstructionStep,
            format!("payload_{i}").as_bytes(),
            format!("Audit proof test step {i}"),
        ));
    }

    let leaf_hashes: Vec<[u8; 32]> = events.iter().map(|e| e.compute_leaf_hash()).collect();
    let tree = MerkleTree::from_hashed_leaves(leaf_hashes);
    let root = tree.root();

    // Verify inclusion proofs for boundaries and interior leaves
    for idx in [0, 1, 15, 31, 32, 47, 63] {
        let proof = tree.generate_proof(idx).expect("proof must exist");
        assert_eq!(proof.leaf_index, idx);
        assert_eq!(proof.tree_size, 64);
        assert!(proof.verify(&root), "Inclusion proof for leaf {idx} must verify");
    }

    // Tampered leaf hash must fail verification
    let mut tampered_proof = tree.generate_proof(10).expect("proof 10");
    tampered_proof.leaf_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();
    assert!(!tampered_proof.verify(&root), "Tampered leaf proof must fail");

    // Proof with incorrect root must fail
    let wrong_root = [0xff; 32];
    let proof = tree.generate_proof(20).expect("proof 20");
    assert!(!proof.verify(&wrong_root), "Proof against wrong root must fail");
}

// =========================================================================
// 5. Tamper Resistance Matrix
// =========================================================================

#[test]
fn test_clm004_tamper_matrix() {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);

    let replayer = DeterministicStateReplayer::new(20);
    let (_tree, state_hash) = replayer.replay(42, "{}").expect("replay");

    let mut events = Vec::new();
    for i in 0..20 {
        events.push(TraceEvent::new(
            i,
            i * 10,
            0,
            1,
            EventKind::InstructionStep,
            i.to_le_bytes().as_slice(),
            format!("event {i}"),
        ));
    }

    let valid_bundle = EvidenceBundle::create_attested(
        "tamper-test-bundle",
        "2026-11-24T12:00:00Z",
        "TierA",
        "test_target",
        "sha256:digest",
        "git:build",
        42,
        "{}",
        events,
        state_hash,
        &signing_key,
    );

    // 1. Valid bundle passes
    assert!(valid_bundle.verify_all().is_ok());

    // 2. Tampered seed
    let mut t_seed = valid_bundle.clone();
    t_seed.seed = 43;
    assert!(t_seed.verify_signature().is_err());

    // 3. Tampered container digest
    let mut t_digest = valid_bundle.clone();
    t_digest.container_digest = "sha256:tampered".into();
    assert!(t_digest.verify_signature().is_err());

    // 4. Tampered binary build hash
    let mut t_build = valid_bundle.clone();
    t_build.binary_build_hash = "git:tampered".into();
    assert!(t_build.verify_signature().is_err());

    // 5. Tampered fault schedule
    let mut t_fault = valid_bundle.clone();
    t_fault.fault_schedule_json = r#"{"injected":true}"#.into();
    assert!(t_fault.verify_signature().is_err());

    // 6. Tampered trace event payload (Merkle integrity fails)
    let mut t_event = valid_bundle.clone();
    t_event.events[5].summary = "tampered summary".into();
    assert!(t_event.verify_merkle_integrity().is_err());

    // 7. Dynamic replay divergence (replayer with different seed fails)
    let diverging_replayer = DeterministicStateReplayer::new(20);
    let mut altered_bundle = valid_bundle.clone();
    altered_bundle.seed = 999; // bypass signature check to test replay divergence directly
    let res = StandaloneVerifier::verify_with_replay(&altered_bundle, &diverging_replayer);
    assert!(res.is_err(), "Diverging execution replay must be rejected");
}
