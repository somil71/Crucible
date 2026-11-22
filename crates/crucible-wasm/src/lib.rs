//! Crucible Tier B: WebAssembly Runtime via Wasmtime.
//!
//! Provides deterministic fuel-metered execution, virtual WASI interception
//! (clocks, entropy, sockets/IPC), and byte-exact memory snapshotting.

pub mod runtime;
pub mod wasi;
pub mod snapshot;
pub mod cluster;

pub use runtime::{WasmRuntimeConfig, WasmInstance};
pub use snapshot::WasmSnapshot;
pub use cluster::{WasmCluster, WasmClusterConfig};
