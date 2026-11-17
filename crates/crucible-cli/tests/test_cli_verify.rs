use crucible_trace::EvidenceBundle;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;

#[test]
fn test_cli_evidence_bundle_lifecycle() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let bundle = EvidenceBundle::create(
        42,
        "sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069".into(),
        "git:9327359".into(),
        r#"{"seed":42,"faults":[]}"#.into(),
        b"execution trace binary bytes for determinism audit",
        &signing_key,
    );

    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let temp_path = std::env::temp_dir().join("test_evidence.crucible");
    fs::write(&temp_path, &json).unwrap();

    // Verify
    let loaded: EvidenceBundle = serde_json::from_str(&fs::read_to_string(&temp_path).unwrap()).unwrap();
    assert!(loaded.verify().is_ok());

    let _ = fs::remove_file(temp_path);
}
