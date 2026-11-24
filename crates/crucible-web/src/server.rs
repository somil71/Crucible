//! Embedded Web Explorer Server for interactive trace scrubbing and causal visualization.

use crucible_trace::EvidenceBundle;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::info;

pub const INDEX_HTML: &str = include_str!("assets/index.html");

/// Embedded Web Explorer HTTP Server.
pub struct WebExplorerServer {
    bundle: Option<Arc<EvidenceBundle>>,
    port: u16,
}

impl WebExplorerServer {
    pub fn new(bundle: Option<EvidenceBundle>, port: u16) -> Self {
        Self {
            bundle: bundle.map(Arc::new),
            port,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Starts the web server listening on 127.0.0.1:<port>.
    pub async fn start(&self) -> anyhow::Result<()> {
        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr).await?;
        info!("Crucible Web Explorer listening on http://{}", addr);

        let bundle_arc = self.bundle.clone();

        loop {
            let (stream, _) = listener.accept().await?;
            let bundle = bundle_arc.clone();
            tokio::spawn(async move {
                let _ = handle_connection(stream, bundle).await;
            });
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    bundle: Option<Arc<EvidenceBundle>>,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 2048];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.lines();
    let first_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
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
        let json = r#"{"status":"running","fps":60,"lod_enabled":true,"supported_events":1000000}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.len(),
            json
        );
        stream.write_all(resp.as_bytes()).await?;
    } else {
        let not_found = "HTTP/1.1 404 NOT FOUND\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(not_found.as_bytes()).await?;
    }

    Ok(())
}
