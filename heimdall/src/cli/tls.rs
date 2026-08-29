//! TLS trust-material commands with stable JSON output for agents.

use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

#[derive(clap::Subcommand, Debug)]
pub enum TlsCmd {
    /// Generate a local CA certificate and protected signing key for relay mode.
    InitCa(InitCaArgs),
}

#[derive(clap::Args, Debug)]
pub struct InitCaArgs {
    /// Directory receiving ca.pem and ca-key.pem.
    #[arg(long, default_value = "/var/lib/heimdall/tls")]
    dir: PathBuf,

    /// Replace both files if they already exist.
    #[arg(long)]
    force: bool,

    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct CaReport {
    contract: &'static str,
    ca_cert: String,
    ca_cert_sha256: String,
    ca_key: String,
    config: ConfigSnippet,
}

#[derive(Serialize)]
struct ConfigSnippet {
    mode: &'static str,
    ca_cert: String,
    ca_key: String,
}

pub fn run(command: TlsCmd) -> Result<()> {
    match command {
        TlsCmd::InitCa(args) => init_ca(args),
    }
}

fn init_ca(args: InitCaArgs) -> Result<()> {
    fs::create_dir_all(&args.dir)
        .with_context(|| format!("create TLS directory {}", args.dir.display()))?;
    let cert_path = args.dir.join("ca.pem");
    let key_path = args.dir.join("ca-key.pem");
    if !args.force {
        anyhow::ensure!(
            !cert_path.exists() && !key_path.exists(),
            "refusing to replace existing CA material; use --force only when every client will trust the new CA"
        );
    }

    let key = KeyPair::generate().context("generate CA private key")?;
    let params = local_ca_params();
    let certificate = params
        .self_signed(&key)
        .context("generate CA certificate")?;

    write_private(&key_path, key.serialize_pem().as_bytes())?;
    fs::write(&cert_path, certificate.pem())
        .with_context(|| format!("write CA certificate {}", cert_path.display()))?;

    let report = CaReport {
        contract: "heimdall.tls-ca/v2",
        ca_cert: cert_path.display().to_string(),
        ca_cert_sha256: sha256_der(certificate.der().as_ref()),
        ca_key: key_path.display().to_string(),
        config: ConfigSnippet {
            mode: "relay",
            ca_cert: cert_path.display().to_string(),
            ca_key: key_path.display().to_string(),
        },
    };
    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("CA certificate: {}", report.ca_cert);
        println!("CA certificate SHA-256: {}", report.ca_cert_sha256);
        println!("CA private key: {}", report.ca_key);
        println!(
            "Trust the certificate in the wrapped client, then configure decrypt.mode = relay."
        );
    }
    Ok(())
}

fn local_ca_params() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .key_usages
        .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Heimdall Local CA");
    params.distinguished_name = name;
    params
}

pub(crate) fn certificate_sha256(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    let (_, pem) = parse_x509_pem(&bytes).ok()?;
    parse_x509_certificate(&pem.contents).ok()?;
    Some(sha256_der(&pem.contents))
}

fn sha256_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn write_private(path: &std::path::Path, content: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    std::io::Write::write_all(
        &mut options
            .open(path)
            .with_context(|| format!("write CA private key {}", path.display()))?,
        content,
    )?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("secure CA private key {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{local_ca_params, sha256_der};
    use rcgen::KeyPair;
    use x509_parser::parse_x509_certificate;

    #[test]
    fn certificate_fingerprint_is_lowercase_sha256() {
        assert_eq!(
            sha256_der(b"heimdall-ca-fixture"),
            "b155bce3a058aa66bb341f8e6aa0d42b79d37bff50cdc30670e45dc0a4825e95"
        );
    }

    #[test]
    fn local_ca_has_explicit_signing_key_usage() {
        let key = KeyPair::generate().unwrap();
        let certificate = local_ca_params().self_signed(&key).unwrap();
        let (_, parsed) = parse_x509_certificate(certificate.der()).unwrap();
        let usage = parsed.key_usage().unwrap().unwrap();

        assert!(usage.value.key_cert_sign());
        assert!(usage.value.crl_sign());
    }
}
