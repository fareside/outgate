//! Command-line interface definitions.
//!
//! Outgate is a single-purpose binary: running it starts the proxy. This module
//! owns only the bind address and CA bundle path, plus the environment
//! variable bindings used by local process managers.

use clap::Parser;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

/// Top-level CLI parser.
#[derive(Parser, Clone)]
#[command(version, about = "Programmable local HTTP/TLS egress proxy firewall")]
pub struct Cli {
    /// Host to bind the proxy listener on.
    #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST), env = "HOST")]
    host: IpAddr,

    /// Port to bind the proxy listener on.
    #[arg(long, default_value_t = 9191, env = "PORT")]
    port: u16,

    /// Path to the private CA PEM bundle.
    ///
    /// The bundle contains both the public CA certificate and private signing
    /// key. `/_outgate/ca.pem` serves a public-only copy for clients to trust.
    #[arg(long, default_value = "cert/outgate-root-ca.pem", env = "CERTIFICATE")]
    certificate: PathBuf,

    /// JavaScript module or module directory used to intercept proxied requests.
    ///
    /// Each module must export `default async function intercept(request, env,
    /// ctx)`. A directory is selected per request by the proxy-auth username.
    #[arg(long, env = "INTERCEPT")]
    intercept: Option<PathBuf>,
}

impl Cli {
    /// Socket address to bind.
    pub fn addr(&self) -> SocketAddr {
        SocketAddr::new(self.host, self.port)
    }

    /// Path to the private root CA PEM bundle.
    pub fn certificate(&self) -> &Path {
        self.certificate.as_path()
    }

    /// Optional JavaScript intercept module path.
    pub fn intercept(&self) -> Option<&Path> {
        self.intercept.as_deref()
    }
}
