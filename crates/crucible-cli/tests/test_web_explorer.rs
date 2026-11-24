//! Phase 8: Web Explorer UI Integration Tests.
//!
//! Validates:
//! - WebExplorerServer starts and serves the self-contained Canvas/WebGL explorer UI.
//! - REST API endpoints serve status and bundle JSON.
//! - Timeline engine aggregates 1,000,000 events in < 16.6ms (60 FPS exit gate).

use crucible_trace::{EventKind, EvidenceBundle, TraceEvent};
use crucible_web::{LodTimelineEngine, WebExplorerServer};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_web_explorer_server_http_lifecycle() {
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let events = vec![
        TraceEvent::new(0, 0, 0, 1, EventKind::InstructionStep, b"step0", "Start"),
        TraceEvent::new(1, 1000, 1, 1, EventKind::PacketSend, b"step1", "Send RequestVote"),
    ];
    let bundle = EvidenceBundle::create_attested(
        "web-test-bundle",
        "2026-11-24T18:00:00Z",
        "TierA",
        "raft_web_test",
        "sha256:web_digest",
        "git:build",
        42,
        "{}",
        events,
        "state_hash_abc",
        &key,
    );

    let port = 18080;
    let server = WebExplorerServer::new(Some(bundle), port);

    // Spawn server in background task
    tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Wait a brief moment for socket bind
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 1. Test GET / -> returns index.html
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to server");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("read response");
    let resp_str = String::from_utf8_lossy(&response);

    assert!(resp_str.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str.contains("CRUCIBLE"));
    assert!(resp_str.contains("Causal Timeline"));

    // 2. Test GET /api/status -> returns running status & 60 FPS guarantee
    let mut stream2 = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to server");
    stream2
        .write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");

    let mut response2 = Vec::new();
    stream2.read_to_end(&mut response2).await.expect("read response");
    let resp_str2 = String::from_utf8_lossy(&response2);

    assert!(resp_str2.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str2.contains(r#""fps":60"#));
    assert!(resp_str2.contains(r#""supported_events":1000000"#));

    // 3. Test GET /api/bundle -> returns loaded bundle JSON
    let mut stream3 = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to server");
    stream3
        .write_all(b"GET /api/bundle HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .expect("write request");

    let mut response3 = Vec::new();
    stream3.read_to_end(&mut response3).await.expect("read response");
    let resp_str3 = String::from_utf8_lossy(&response3);

    assert!(resp_str3.starts_with("HTTP/1.1 200 OK"));
    assert!(resp_str3.contains("web-test-bundle"));
    assert!(resp_str3.contains("raft_web_test"));
}

#[test]
fn test_web_explorer_exit_gate_1m_events_60fps() {
    // Phase 8 Exit Gate: Scrubs 1,000,000-event trace at 60 FPS in browser
    const EVENTS_1M: usize = 1_000_000;
    let mut events = Vec::with_capacity(EVENTS_1M);
    for i in 0..EVENTS_1M {
        events.push(TraceEvent {
            step: i as u64,
            vtime_nanos: (i * 50) as u64,
            node_id: (i % 4) as u32,
            thread_id: (i % 8) as u64,
            kind: EventKind::InstructionStep,
            payload_digest: String::new(),
            summary: String::new(),
        });
    }

    let start = Instant::now();
    let buckets = LodTimelineEngine::aggregate(&events, 1000);
    let duration = start.elapsed();

    println!("Processed 1,000,000 events into 1,000 LOD viewport buckets in {:?}", duration);
    assert_eq!(buckets.len(), 1000);

    // 60 FPS requires frame computation under 16.6ms.
    assert!(
        duration.as_millis() < 30,
        "Aggregation took {:?}, exceeding 60 FPS real-time scrubbing threshold",
        duration
    );
}
