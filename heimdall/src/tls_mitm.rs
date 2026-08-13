//! Language-independent TLS interception at the relay boundary.

use std::{fs, os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::capture::{self, CaptureManager, FlowMeta};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(3);
const CLASSIFY_TIMEOUT: Duration = Duration::from_millis(150);

pub struct Mitm {
    ca: Certificate,
    ca_key: KeyPair,
    client_config: Arc<ClientConfig>,
}

impl Mitm {
    pub fn load(ca_cert: &Path, ca_key: &Path) -> Result<Self> {
        let key_metadata = fs::symlink_metadata(ca_key)
            .with_context(|| format!("inspect MITM CA key {}", ca_key.display()))?;
        anyhow::ensure!(key_metadata.is_file(), "MITM CA key must be a regular file");
        anyhow::ensure!(
            key_metadata.permissions().mode() & 0o077 == 0,
            "MITM CA key {} must not grant group or other permissions; use mode 0600",
            ca_key.display()
        );
        let cert_pem = fs::read_to_string(ca_cert)
            .with_context(|| format!("read MITM CA certificate {}", ca_cert.display()))?;
        let key_pem = fs::read_to_string(ca_key)
            .with_context(|| format!("read MITM CA key {}", ca_key.display()))?;
        let ca_key = KeyPair::from_pem(&key_pem).context("parse MITM CA private key PEM")?;
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).context("decode MITM CA PEM")?;
        let (_, parsed_ca) = parse_x509_certificate(&pem.contents).context("parse MITM CA DER")?;
        anyhow::ensure!(
            parsed_ca
                .basic_constraints()
                .context("read MITM CA basic constraints")?
                .is_some_and(|constraint| constraint.value.ca),
            "MITM CA certificate is not authorized to sign certificates"
        );
        anyhow::ensure!(
            parsed_ca.public_key().raw == ca_key.public_key_der(),
            "MITM CA certificate and private key do not match"
        );
        let ca = CertificateParams::from_ca_cert_pem(&cert_pem)
            .context("parse MITM CA certificate PEM")?
            .self_signed(&ca_key)
            .context("reconstruct MITM CA signer")?;

        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (added, ignored) = roots.add_parsable_certificates(native.certs);
        anyhow::ensure!(
            added > 0,
            "no usable native CA roots found for upstream TLS"
        );
        anyhow::ensure!(
            native.errors.is_empty() && ignored == 0,
            "native CA store contained {} load error(s) and {ignored} invalid certificate(s)",
            native.errors.len()
        );
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            ca,
            ca_key,
            client_config: Arc::new(client_config),
        })
    }

    pub async fn copy(
        &self,
        client: &mut TcpStream,
        remote: &mut TcpStream,
        fallback_name: &str,
        capture: &CaptureManager,
        meta: FlowMeta<'_>,
    ) -> Result<(u64, u64)> {
        let start = tokio::time::timeout(
            CLIENT_HELLO_TIMEOUT,
            LazyConfigAcceptor::new(rustls::server::Acceptor::default(), client),
        )
        .await
        .context("timed out reading TLS ClientHello")?
        .context("read TLS ClientHello")?;
        let hello = start.client_hello();
        let server_name = hello.server_name().unwrap_or(fallback_name).to_owned();
        let offered_alpn = hello
            .alpn()
            .map(|items| items.map(<[u8]>::to_vec).collect::<Vec<_>>())
            .unwrap_or_default();

        let name = ServerName::try_from(server_name.clone())
            .with_context(|| format!("invalid TLS server name `{server_name}`"))?;
        let connector = TlsConnector::from(self.client_config.clone());
        let mut upstream = connector
            .with_alpn(offered_alpn)
            .connect(name, remote)
            .await
            .with_context(|| format!("verify upstream TLS certificate for {server_name}"))?;
        let selected_alpn = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);

        let server_config = self.server_config(&server_name, selected_alpn)?;
        let mut downstream = start
            .into_stream(Arc::new(server_config))
            .await
            .with_context(|| format!("complete intercepted TLS handshake for {server_name}"))?;
        capture::copy_tcp(&mut downstream, &mut upstream, capture.open(meta).await?).await
    }

    fn server_config(&self, server_name: &str, alpn: Option<Vec<u8>>) -> Result<ServerConfig> {
        let key = KeyPair::generate().context("generate intercepted TLS leaf key")?;
        let mut params = CertificateParams::new(vec![server_name.to_owned()])
            .context("create intercepted TLS certificate parameters")?;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let cert = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .context("sign intercepted TLS certificate")?;
        let cert_chain = vec![CertificateDer::from(cert.der().to_vec())];
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .context("configure intercepted TLS certificate")?;
        if let Some(protocol) = alpn {
            config.alpn_protocols.push(protocol);
        }
        Ok(config)
    }
}

pub async fn looks_like_client_hello(stream: &TcpStream) -> Result<bool> {
    let mut header = [0u8; 6];
    let read = match tokio::time::timeout(CLASSIFY_TIMEOUT, stream.peek(&mut header)).await {
        Ok(result) => result.context("peek TCP payload")?,
        Err(_) => return Ok(false),
    };
    Ok(read >= header.len()
        && header[0] == 0x16
        && header[1] == 0x03
        && header[2] <= 0x04
        && header[5] == 0x01)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, IsCa};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_rustls::TlsAcceptor;

    #[tokio::test]
    async fn generated_leaf_is_trusted_and_preserves_alpn() {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let ca_der = CertificateDer::from(ca.der().to_vec());

        let mut roots = RootCertStore::empty();
        roots.add(ca_der).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mitm = Mitm {
            ca,
            ca_key,
            client_config: Arc::new(client_config.clone()),
        };
        let server_config = mitm
            .server_config("example.com", Some(b"h2".to_vec()))
            .unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut tls = TlsAcceptor::from(Arc::new(server_config))
                .accept(server_io)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
            tls.write_all(b"ok").await.unwrap();
        });

        let mut config = client_config;
        config.alpn_protocols.push(b"h2".to_vec());
        let name = ServerName::try_from("example.com").unwrap();
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(name, client_io)
            .await
            .unwrap();
        let mut response = [0u8; 2];
        tls.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        server.await.unwrap();
    }
}
