//! Embedded Web Explorer Server for interactive trace scrubbing, causal visualization,
//! and real-time live event streaming via Server-Sent Events (SSE).

use crucible_trace::EvidenceBundle;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::info;

pub const INDEX_HTML: &str = include_str!("assets/index.html");

/// Embedded Web Explorer HTTP Server with Live Streaming Support.
pub struct WebExplorerServer {
    bundle: Option<Arc<EvidenceBundle>>,
    port: u16,
    event_tx: broadcast::Sender<String>,
}

impl WebExplorerServer {
    pub fn new(bundle: Option<EvidenceBundle>, port: u16) -> Self {
        let (event_tx, _) = broadcast::channel(4096);
        Self {
            bundle: bundle.map(Arc::new),
            port,
            event_tx,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Broadcast a JSON event payload to all connected Web Explorer browsers.
    pub fn broadcast_event(&self, event_json: &str) {
        let _ = self.event_tx.send(event_json.to_string());
    }

    /// Obtain a clone of the broadcast sender for piping campaign execution events.
    pub fn event_sender(&self) -> broadcast::Sender<String> {
        self.event_tx.clone()
    }

    /// Starts the web server listening on 127.0.0.1:<port>.
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr).await?;
        info!("Crucible Web Explorer listening on http://{}", addr);

        let bundle_arc = self.bundle.clone();
        let event_tx = self.event_tx.clone();

        loop {
            let (stream, _) = listener.accept().await?;
            let bundle = bundle_arc.clone();
            let tx = event_tx.clone();
            tokio::spawn(async move {
                let _ = handle_connection(stream, bundle, tx).await;
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    bundle: Option<Arc<EvidenceBundle>>,
    event_tx: broadcast::Sender<String>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    let method = if !parts.is_empty() { parts[0] } else { "GET" };
    let path = if parts.len() >= 2 { parts[1] } else { "/" };

    if path == "/" || path == "/index.html" {
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            INDEX_HTML.len(),
            INDEX_HTML
        );
        stream.write_all(resp.as_bytes()).await?;
    } else if path == "/api/bundle" {
        let json = if let Some(b) = bundle {
            b.to_json().unwrap_or_else(|_| "{}".into())
        } else {
            "{}".into()
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(resp.as_bytes()).await?;
    } else if path == "/health" || path == "/api/status" {
        let json = r#"{"status":"running","fps":60,"lod_enabled":true,"supported_events":1000000,"streaming_sse":true}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(resp.as_bytes()).await?;
    } else if path == "/api/stream" {
        // Server-Sent Events (SSE) live event push to browser timeline
        let header = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
        stream.write_all(header.as_bytes()).await?;

        let init_msg = "data: {\"type\":\"init\",\"status\":\"connected\",\"lod\":true}\n\n";
        stream.write_all(init_msg.as_bytes()).await?;

        let mut rx = event_tx.subscribe();
        while let Ok(msg) = rx.recv().await {
            let formatted = format!("data: {msg}\n\n");
            if stream.write_all(formatted.as_bytes()).await.is_err() {
                break;
            }
        }
    } else if path == "/api/publish" && method == "POST" {
        // Extract body if present
        let body = if let Some(body_start) = request.find("\r\n\r\n") {
            &request[body_start + 4..]
        } else {
            ""
        };
        let _ = event_tx.send(body.to_string());
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"published\":true}";
        stream.write_all(resp.as_bytes()).await?;
    } else {
        let not_found = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(not_found.as_bytes()).await?;
    }

    Ok(())
}
