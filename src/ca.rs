//! Local certificate authority support.
//!
//! Outgate performs HTTPS MITM by acting as a TLS server after a client's
//! `CONNECT` request. For that to work, the client must trust a local root CA.
//!
//! The important domain distinction is public versus private material:
//!
//! - `PrivateCaBundle` is the persisted secret: CA certificate plus signing key.
//! - `PublicCaCertificate` is safe trust material: only the CA certificate.
//! - `CertificateAuthority` is the runtime signer that mints per-host leaf certs.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio_rustls::TlsAcceptor;

pub type CaResult<T> = Result<T, CaError>;

/// Errors that can occur while loading, generating, or using Outgate's CA.
#[derive(Debug, Error)]
pub enum CaError {
    #[error("certificate path points to a directory, expected a private PEM bundle file: {path}")]
    CertificatePathIsDirectory { path: PathBuf },

    #[error("PEM bundle missing {label} block")]
    MissingPemBlock { label: String },

    #[error("PEM bundle has unterminated {label} block")]
    UnterminatedPemBlock { label: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Pem(#[from] rustls::pki_types::pem::Error),

    #[error(transparent)]
    Rcgen(#[from] rcgen::Error),

    #[error(transparent)]
    Rustls(#[from] rustls::Error),
}

/// Runtime CA signer used to mint intercepted leaf certificates.
#[derive(Clone)]
pub struct CertificateAuthority {
    issuer: Arc<Issuer<'static, KeyPair>>,
    private_bundle_path: Arc<PathBuf>,
    public_cert_path: Arc<PathBuf>,
}

impl CertificateAuthority {
    /// Load the private CA bundle from `certificate_path`, or generate it.
    pub fn load_or_create(certificate_path: &Path) -> CaResult<Self> {
        PrivateCaBundle::load_or_create(certificate_path)?.into_authority()
    }

    /// Filesystem path to the private CA bundle.
    pub fn bundle_path(&self) -> &Path {
        self.private_bundle_path.as_path()
    }

    /// Filesystem path to the temp public-only certificate.
    pub fn public_cert_path(&self) -> &Path {
        self.public_cert_path.as_path()
    }

    /// Build a TLS acceptor for one intercepted server name.
    ///
    /// This creates a fresh leaf certificate with the requested DNS name and
    /// signs it with the local root CA. The acceptor advertises only HTTP/1.1
    /// through ALPN because the rest of this proxy only speaks HTTP/1.1.
    pub fn tls_acceptor(&self, server_name: &str) -> CaResult<TlsAcceptor> {
        let mut params = CertificateParams::new(vec![server_name.to_string()])?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, server_name);
        params.distinguished_name = distinguished_name;

        let leaf_key = KeyPair::generate()?;
        let cert = params.signed_by(&leaf_key, self.issuer.as_ref())?;
        let key_der = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key_der)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Persisted private CA material.
///
/// This bundle is deliberately a single PEM file with two blocks:
///
/// ```text
/// -----BEGIN CERTIFICATE-----
/// ...
/// -----END CERTIFICATE-----
/// -----BEGIN PRIVATE KEY-----
/// ...
/// -----END PRIVATE KEY-----
/// ```
struct PrivateCaBundle {
    path: PathBuf,
    public_cert: PublicCaCertificate,
    signing_key: KeyPair,
}

impl PrivateCaBundle {
    /// Load an existing bundle, or create and persist a new one.
    fn load_or_create(path: &Path) -> CaResult<Self> {
        Self::ensure_file_path(path)?;

        if path.exists() {
            Self::load(path)
        } else {
            let bundle = Self::generate(path)?;
            bundle.persist()?;
            Ok(bundle)
        }
    }

    /// Load a private CA bundle from PEM.
    fn load(path: &Path) -> CaResult<Self> {
        let pem = fs::read_to_string(path)?;
        let public_cert = PublicCaCertificate::from_bundle_pem(&pem)?;
        let key_der = PrivateKeyDer::from_pem_slice(pem.as_bytes())?;
        let signing_key = KeyPair::try_from(&key_der)?;

        Ok(Self {
            path: path.to_path_buf(),
            public_cert,
            signing_key,
        })
    }

    /// Generate a new private CA bundle.
    fn generate(path: &Path) -> CaResult<Self> {
        let mut params = CertificateParams::new(Vec::new())?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::OrganizationName, "Outgate");
        distinguished_name.push(DnType::CommonName, "Outgate Local MITM CA");
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let signing_key = KeyPair::generate()?;
        let cert = params.self_signed(&signing_key)?;
        let public_cert = PublicCaCertificate::new(cert.pem(), cert.der().as_ref().to_vec());

        Ok(Self {
            path: path.to_path_buf(),
            public_cert,
            signing_key,
        })
    }

    /// Persist this private bundle to disk with restrictive permissions.
    fn persist(&self) -> CaResult<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(self.path.as_path(), self.to_pem())?;
        restrict_key_permissions(self.path.as_path())?;
        Ok(())
    }

    /// Convert this persisted domain object into a runtime signer.
    fn into_authority(self) -> CaResult<CertificateAuthority> {
        let cert_der = CertificateDer::from(self.public_cert.der.clone());
        let issuer = Issuer::from_ca_cert_der(&cert_der, self.signing_key)?;
        let public_cert_path = self.public_cert.write_to_temp_file()?;

        Ok(CertificateAuthority {
            issuer: Arc::new(issuer),
            private_bundle_path: Arc::new(self.path),
            public_cert_path: Arc::new(public_cert_path),
        })
    }

    /// Serialize the single-file private CA bundle.
    fn to_pem(&self) -> String {
        format!(
            "{}\n{}",
            self.public_cert.pem,
            self.signing_key.serialize_pem()
        )
    }

    /// Reject directories early so later read/write errors are less mysterious.
    fn ensure_file_path(path: &Path) -> CaResult<()> {
        if path.is_dir() {
            return Err(CaError::CertificatePathIsDirectory {
                path: path.to_path_buf(),
            });
        }

        Ok(())
    }
}

/// Public CA certificate that clients may trust.
struct PublicCaCertificate {
    pem: String,
    der: Vec<u8>,
}

impl PublicCaCertificate {
    fn new(pem: String, der: Vec<u8>) -> Self {
        Self { pem, der }
    }

    /// Extract the public certificate from a private PEM bundle.
    fn from_bundle_pem(bundle_pem: &str) -> CaResult<Self> {
        let pem = extract_pem_block(bundle_pem, "CERTIFICATE")?;
        let der = CertificateDer::from_pem_slice(bundle_pem.as_bytes())?
            .as_ref()
            .to_vec();
        Ok(Self { pem, der })
    }

    /// Write a process-local public copy for humans and CLI tools.
    fn write_to_temp_file(&self) -> CaResult<PathBuf> {
        let path = public_cert_temp_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(path.as_path(), self.pem.as_bytes())?;
        Ok(path)
    }
}

/// Pick a process-local temp path for the public CA certificate.
///
/// Including the process id avoids two Outgate instances racing over the same
/// public certificate path.
fn public_cert_temp_path() -> PathBuf {
    std::env::temp_dir()
        .join("outgate")
        .join(format!("outgate-root-ca-public-{}.pem", std::process::id()))
}

/// Extract the first PEM block with a specific label and preserve its armor.
///
/// `rustls-pki-types` can decode PEM blocks, but it does not re-encode them.
/// Keeping this tiny extractor lets the public certificate be written exactly
/// as PEM without retaining a separate public-cert file beside the secret.
fn extract_pem_block(pem: &str, label: &str) -> CaResult<String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem.find(&begin).ok_or_else(|| CaError::MissingPemBlock {
        label: label.to_owned(),
    })?;
    let after_start = start + begin.len();
    let relative_end =
        pem[after_start..]
            .find(&end)
            .ok_or_else(|| CaError::UnterminatedPemBlock {
                label: label.to_owned(),
            })?;
    let end_index = after_start + relative_end + end.len();

    Ok(format!("{}\n", pem[start..end_index].trim_end()))
}

/// Restrict the private CA bundle to the current user on Unix-like systems.
#[cfg(unix)]
fn restrict_key_permissions(path: &Path) -> CaResult<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Best-effort no-op on non-Unix platforms.
#[cfg(not(unix))]
fn restrict_key_permissions(_key_path: &Path) -> CaResult<()> {
    Ok(())
}
