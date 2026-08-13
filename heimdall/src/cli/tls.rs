//! TLS trust-material commands with stable JSON output for agents.

use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
use serde::Serialize;

#[derive(clap::Subcommand, Debug)]
pub enum TlsCmd {
    /// Generate a local CA certificate and protected signing key for MITM mode.
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
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "Heimdall Local CA");
    params.distinguished_name = name;
    let certificate = params
        .self_signed(&key)
        .context("generate CA certificate")?;

    write_private(&key_path, key.serialize_pem().as_bytes())?;
    fs::write(&cert_path, certificate.pem())
        .with_context(|| format!("write CA certificate {}", cert_path.display()))?;

    let report = CaReport {
        contract: "heimdall.tls-ca/v1",
        ca_cert: cert_path.display().to_string(),
        ca_key: key_path.display().to_string(),
        config: ConfigSnippet {
            mode: "mitm",
            ca_cert: cert_path.display().to_string(),
            ca_key: key_path.display().to_string(),
        },
    };
    if args.json {
        println!("{}", serde_json::to_string(&report)?);
    } else {
        println!("CA certificate: {}", report.ca_cert);
        println!("CA private key: {}", report.ca_key);
        println!(
            "Trust the certificate in the wrapped client, then configure decrypt.mode = mitm."
        );
    }
    Ok(())
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
