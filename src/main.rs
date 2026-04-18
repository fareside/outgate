//! Binary entrypoint for Outgate.
//!
//! The interesting proxy mechanics live in the sibling modules. `main` stays
//! intentionally boring: initialize logging, parse CLI arguments, and start the
//! long-running proxy server.

mod body;
mod ca;
mod cli;
mod interceptor;
mod kv;
mod proxy;
mod sig_down;

use clap::Parser;
use cli::Cli;
use dotenvy::dotenv;
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Start the Tokio runtime and report failures with user-facing error text.
///
/// ```text
/// cargo run
/// ```
#[tokio::main]
async fn main() -> ExitCode {
    dotenv().ok();

    init_crypto_provider();
    init_tracing();

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parse CLI options and run the proxy until interrupted.
async fn run() -> Result<(), BoxError> {
    let sig_down = sig_down::SigDown::try_new()?;
    Ok(proxy::serve(Cli::parse(), sig_down.cancellation_token()).await?)
}

/// Select the rustls process-wide crypto provider before any TLS code runs.
///
/// Outgate uses rustls through both the local MITM server and reqwest. Installing
/// the provider explicitly keeps runtime behavior stable even if dependency
/// feature unification would otherwise make rustls see more than one provider.
fn init_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Configure tracing once for the whole process.
///
/// `RUST_LOG` can override the default. The default is intentionally broad
/// `info` rather than `outgate=info` because this is a binary crate and the
/// useful target names may be module-path dependent during refactors.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}
