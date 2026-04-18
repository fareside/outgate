//! Run one command through a running Outgate proxy.
//!
//! Downloads Outgate's public CA certificate into a private temp directory,
//! injects common proxy/trust environment variables, then execs the wrapped
//! command with inherited stdio.
//!
//! Usage:
//!   membrane http://127.0.0.1:9191 -- curl https://example.com

use clap::Parser;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process;
use url::Url;

const ADMIN_CA_PATH: &str = "/_outgate/ca.pem";
const MAX_CA_BYTES: u64 = 1024 * 1024;

#[derive(Parser)]
#[command(
    name = "membrane",
    about = "Run a command through a running Outgate proxy",
    override_usage = "membrane [--agent-id <id>] <proxy-url> -- <command> [args...]",
    after_help = "Injected env:\n  http_proxy, https_proxy, HTTP_PROXY, HTTPS_PROXY\n  all_proxy, ALL_PROXY, NODE_USE_ENV_PROXY\n  NODE_EXTRA_CA_CERTS, CURL_CA_BUNDLE, SSL_CERT_FILE"
)]
struct Cli {
    /// Set proxy auth username to select an agent policy
    #[arg(long)]
    agent_id: Option<String>,

    /// Outgate proxy URL (e.g. http://127.0.0.1:9191)
    proxy_url: String,

    /// Command and arguments to run
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() {
    match run() {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("membrane: {e}");
            process::exit(1);
        }
    }
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let mut proxy_url = normalize_proxy_url(&cli.proxy_url)?;

    if let Some(agent_id) = &cli.agent_id {
        proxy_url
            .set_username(agent_id)
            .map_err(|()| format!("could not set username on proxy URL: {proxy_url}"))?;
        proxy_url
            .set_password(Some("x"))
            .map_err(|()| format!("could not set password on proxy URL: {proxy_url}"))?;
    }

    let temp_dir = TempDir::create()?;
    let ca_path = temp_dir.path().join("outgate-root-ca-public.pem");

    let pem = download_public_ca(&proxy_url)?;
    fs::write(&ca_path, pem.as_bytes())?;
    #[cfg(unix)]
    set_private_permissions(&ca_path)?;

    run_command(&cli.command, &proxy_url, &ca_path)
}

fn normalize_proxy_url(raw: &str) -> Result<Url, Box<dyn std::error::Error>> {
    let mut url = Url::parse(raw).map_err(|_| format!("invalid proxy URL: {raw}"))?;

    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(format!("unsupported proxy URL protocol: {}", url.scheme()).into());
    }

    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);

    Ok(url)
}

fn download_public_ca(proxy_url: &Url) -> Result<String, Box<dyn std::error::Error>> {
    let mut ca_url = proxy_url.clone();
    ca_url.set_path(ADMIN_CA_PATH);
    // Strip any credentials that may be in the proxy URL.
    ca_url.set_username("").ok();
    ca_url.set_password(None).ok();

    let response = reqwest::blocking::get(ca_url.as_str())?;

    if !response.status().is_success() {
        return Err(format!("{ca_url} returned HTTP {}", response.status()).into());
    }

    let mut body = Vec::new();
    response.take(MAX_CA_BYTES + 1).read_to_end(&mut body)?;

    if body.len() as u64 > MAX_CA_BYTES {
        return Err(format!("{ca_url} returned more than {MAX_CA_BYTES} bytes").into());
    }

    let pem = String::from_utf8(body).map_err(|_| format!("{ca_url} returned non-UTF-8 body"))?;

    if !pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err(format!("{ca_url} did not return a PEM certificate").into());
    }

    Ok(pem)
}

fn run_command(
    command: &[String],
    proxy_url: &Url,
    ca_path: &Path,
) -> Result<i32, Box<dyn std::error::Error>> {
    let (program, args) = command.split_first().expect("command is non-empty");
    let proxy_str = proxy_url.as_str();
    let ca_str = ca_path.to_string_lossy();

    let mut child = process::Command::new(program)
        .args(args)
        .env("http_proxy", proxy_str)
        .env("https_proxy", proxy_str)
        .env("HTTP_PROXY", proxy_str)
        .env("HTTPS_PROXY", proxy_str)
        .env("all_proxy", proxy_str)
        .env("ALL_PROXY", proxy_str)
        .env("NODE_USE_ENV_PROXY", "1")
        .env("NODE_EXTRA_CA_CERTS", ca_str.as_ref())
        .env("CURL_CA_BUNDLE", ca_str.as_ref())
        .env("SSL_CERT_FILE", ca_str.as_ref())
        .stdin(process::Stdio::inherit())
        .stdout(process::Stdio::inherit())
        .stderr(process::Stdio::inherit())
        .spawn()?;

    let status = child.wait()?;

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return Ok(128 + signal);
        }
    }

    Ok(status.code().unwrap_or(1))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// A temporary directory that is deleted when dropped.
struct TempDir(PathBuf);

impl TempDir {
    fn create() -> std::io::Result<Self> {
        let base = std::env::temp_dir();
        // Use process ID + a counter for a unique-enough name without extra deps.
        let dir = base.join(format!(
            "outgate-membrane-{}-{}",
            process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir(&dir)?;
        Ok(Self(dir))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
