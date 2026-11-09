use crucible_trace::EvidenceBundle;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn sample_bundle(signing_key: &SigningKey) -> EvidenceBundle {
    EvidenceBundle::create(
        42,
        "sha256:container_digest_test".into(),
        "git:build_hash_test".into(),
        r#"{"seed":42,"faults":[]}"#.into(),
        b"sample trace byte buffer",
        signing_key,
    )
}

// ==========================================
// 1. Valid Signature & Lifecycle (10 tests)
// ==========================================

#[test]
fn test_trace_bundle_create_and_verify() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    assert!(bundle.verify().is_ok());
}

#[test]
fn test_trace_bundle_empty_trace_valid() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = EvidenceBundle::create(
        1,
        "digest".into(),
        "build".into(),
        "[]".into(),
        b"",
        &key,
    );
    assert!(bundle.verify().is_ok());
}

#[test]
fn test_trace_bundle_large_trace_valid() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let large_trace = vec![0x42u8; 100_000];
    let bundle = EvidenceBundle::create(
        100,
        "digest".into(),
        "build".into(),
        "[]".into(),
        &large_trace,
        &key,
    );
    assert!(bundle.verify().is_ok());
}

#[test]
fn test_trace_bundle_public_key_len() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    assert_eq!(bundle.public_key_bytes.len(), 32);
}

#[test]
fn test_trace_bundle_signature_len() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    assert_eq!(bundle.signature_bytes.len(), 64);
}

#[test]
fn test_trace_bundle_trace_hash_hex_len() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    assert_eq!(bundle.trace_hash.len(), 64); // SHA256 hex encoded
}

#[test]
fn test_trace_bundle_distinct_keys_distinct_signatures() {
    let mut rng = OsRng;
    let k1 = SigningKey::generate(&mut rng);
    let k2 = SigningKey::generate(&mut rng);
    let b1 = sample_bundle(&k1);
    let b2 = sample_bundle(&k2);
    assert_ne!(b1.signature_bytes, b2.signature_bytes);
    assert_ne!(b1.public_key_bytes, b2.public_key_bytes);
}

#[test]
fn test_trace_bundle_clone_equality() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    assert_eq!(bundle.seed, bundle.clone().seed);
    assert_eq!(bundle.signature_bytes, bundle.clone().signature_bytes);
}

#[test]
fn test_trace_bundle_deterministic_hash_for_same_trace() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let b1 = sample_bundle(&key);
    let b2 = sample_bundle(&key);
    assert_eq!(b1.trace_hash, b2.trace_hash);
}

#[test]
fn test_trace_bundle_seed_stored() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = EvidenceBundle::create(777, "d".into(), "b".into(), "f".into(), b"t", &key);
    assert_eq!(bundle.seed, 777);
}

// ==========================================
// 2. Tamper Detection & Mutations (10 tests)
// ==========================================

#[test]
fn test_tamper_seed_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.seed ^= 1;
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_container_digest_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.container_digest.push_str("_tampered");
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_build_hash_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.binary_build_hash.push_str("_corrupted");
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_fault_schedule_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.fault_schedule_json = r#"{"seed":42,"faults":[{"action":"CrashNode"}]}"#.into();
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_trace_hash_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.trace_hash = "0000000000000000000000000000000000000000000000000000000000000000".into();
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_signature_single_byte_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.signature_bytes[0] ^= 0xFF;
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_public_key_single_byte_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.public_key_bytes[0] ^= 0xFF;
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_swap_public_key_other_key() {
    let mut rng = OsRng;
    let k1 = SigningKey::generate(&mut rng);
    let k2 = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&k1);
    bundle.public_key_bytes = k2.verifying_key().to_bytes().to_vec();
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_empty_signature_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.signature_bytes.clear();
    assert!(bundle.verify().is_err());
}

#[test]
fn test_tamper_empty_public_key_detected() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.public_key_bytes.clear();
    assert!(bundle.verify().is_err());
}

// ==========================================
// 3. Serialization & Wire Format (10 tests)
// ==========================================

#[test]
fn test_serde_json_roundtrip() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let json = serde_json::to_string(&bundle).unwrap();
    let deser: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert!(deser.verify().is_ok());
    assert_eq!(bundle.seed, deser.seed);
}

#[test]
fn test_serde_pretty_json_roundtrip() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let deser: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert!(deser.verify().is_ok());
}

#[test]
fn test_serde_json_contains_fields() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let json = serde_json::to_string(&bundle).unwrap();
    assert!(json.contains("seed"));
    assert!(json.contains("container_digest"));
    assert!(json.contains("binary_build_hash"));
    assert!(json.contains("trace_hash"));
    assert!(json.contains("signature_bytes"));
}

#[test]
fn test_serde_invalid_json_fails() {
    let res: Result<EvidenceBundle, _> = serde_json::from_str("{ bad json }");
    assert!(res.is_err());
}

#[test]
fn test_serde_missing_field_fails() {
    let res: Result<EvidenceBundle, _> = serde_json::from_str(r#"{"seed":42}"#);
    assert!(res.is_err());
}

#[test]
fn test_serde_extra_whitespace_tolerated() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let json = format!("   \n\t {}\n\n ", serde_json::to_string(&bundle).unwrap());
    let deser: EvidenceBundle = serde_json::from_str(&json).unwrap();
    assert!(deser.verify().is_ok());
}

#[test]
fn test_serde_container_digest_preserved() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let deser: EvidenceBundle = serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
    assert_eq!(bundle.container_digest, deser.container_digest);
}

#[test]
fn test_serde_build_hash_preserved() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let deser: EvidenceBundle = serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
    assert_eq!(bundle.binary_build_hash, deser.binary_build_hash);
}

#[test]
fn test_serde_fault_schedule_preserved() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let deser: EvidenceBundle = serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
    assert_eq!(bundle.fault_schedule_json, deser.fault_schedule_json);
}

#[test]
fn test_serde_trace_hash_preserved() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    let deser: EvidenceBundle = serde_json::from_str(&serde_json::to_string(&bundle).unwrap()).unwrap();
    assert_eq!(bundle.trace_hash, deser.trace_hash);
}

// ==========================================
// 4. Crypto Bounds & Edge Cases (10 tests)
// ==========================================

#[test]
fn test_crypto_truncated_public_key() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.public_key_bytes.truncate(31);
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_extended_public_key() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.public_key_bytes.push(0x00);
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_truncated_signature() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.signature_bytes.truncate(63);
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_extended_signature() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.signature_bytes.push(0x00);
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_all_zeros_signature() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.signature_bytes = vec![0u8; 64];
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_all_ones_signature() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.signature_bytes = vec![0xFFu8; 64];
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_all_zeros_public_key() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let mut bundle = sample_bundle(&key);
    bundle.public_key_bytes = vec![0u8; 32];
    assert!(bundle.verify().is_err());
}

#[test]
fn test_crypto_zero_seed_bundle() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = EvidenceBundle::create(0, "d".into(), "b".into(), "[]".into(), b"", &key);
    assert!(bundle.verify().is_ok());
    assert_eq!(bundle.seed, 0);
}

#[test]
fn test_crypto_max_seed_bundle() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = EvidenceBundle::create(u64::MAX, "d".into(), "b".into(), "[]".into(), b"", &key);
    assert!(bundle.verify().is_ok());
    assert_eq!(bundle.seed, u64::MAX);
}

#[test]
fn test_crypto_repeated_verification_idempotent() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let bundle = sample_bundle(&key);
    for _ in 0..10 {
        assert!(bundle.verify().is_ok());
    }
}
