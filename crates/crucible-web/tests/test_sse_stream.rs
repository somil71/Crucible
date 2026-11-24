use crucible_web::WebExplorerServer;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn test_web_explorer_sse_streaming() {
    let port = 18088;
    let server = WebExplorerServer::new(None, port);
    let event_tx = server.event_sender();

    tokio::spawn(async move {
        let _ = server.start().await;
    });

    // Give server moment to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Connect client
    let mut client = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("Must connect to SSE endpoint");

    let req = "GET /api/stream HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n";
    client.write_all(req.as_bytes()).await.unwrap();

    let mut buf = [0u8; 1024];
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    assert!(resp.contains("200 OK"));
    assert!(resp.contains("text/event-stream"));
    assert!(resp.contains("data: {\"type\":\"init\""));

    // Broadcast a test live event
    event_tx.send("{\"type\":\"event\",\"id\":42}".to_string()).unwrap();

    // Read streamed event
    let n2 = client.read(&mut buf).await.unwrap();
    let resp2 = String::from_utf8_lossy(&buf[..n2]);
    assert!(resp2.contains("data: {\"type\":\"event\",\"id\":42}"));
}
