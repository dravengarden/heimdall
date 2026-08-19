//! Language-independent TLS interception at the relay boundary.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use rcgen::{Certificate, CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::warn;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

use crate::{
    capture::{self, CaptureManager, FlowMeta},
    event_log::FlowEventClient,
};

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(3);
const CLASSIFY_TIMEOUT: Duration = Duration::from_millis(150);

pub struct RelayTls {
    ca: Certificate,
    ca_key: KeyPair,
    client_config: Arc<ClientConfig>,
}

pub struct RelayCopyReport {
    pub client_to_remote_bytes: u64,
    pub remote_to_client_bytes: u64,
    pub server_name: String,
    pub version: String,
    pub cipher: String,
    pub alpn: Option<String>,
    pub latency_us: u64,
}

impl RelayTls {
    pub fn load(ca_cert: &Path, ca_key: &Path) -> Result<Self> {
        let key_metadata = fs::symlink_metadata(ca_key)
            .with_context(|| format!("inspect relay TLS CA key {}", ca_key.display()))?;
        anyhow::ensure!(
            key_metadata.is_file(),
            "relay TLS CA key must be a regular file"
        );
        anyhow::ensure!(
            key_metadata.permissions().mode() & 0o077 == 0,
            "relay TLS CA key {} must not grant group or other permissions; use mode 0600",
            ca_key.display()
        );
        let cert_pem = fs::read_to_string(ca_cert)
            .with_context(|| format!("read relay TLS CA certificate {}", ca_cert.display()))?;
        let key_pem = fs::read_to_string(ca_key)
            .with_context(|| format!("read relay TLS CA key {}", ca_key.display()))?;
        let ca_key = KeyPair::from_pem(&key_pem).context("parse relay TLS CA private key PEM")?;
        let (_, pem) = parse_x509_pem(cert_pem.as_bytes()).context("decode relay TLS CA PEM")?;
        let (_, parsed_ca) =
            parse_x509_certificate(&pem.contents).context("parse relay TLS CA DER")?;
        anyhow::ensure!(
            parsed_ca
                .basic_constraints()
                .context("read relay TLS CA basic constraints")?
                .is_some_and(|constraint| constraint.value.ca),
            "relay TLS CA certificate is not authorized to sign certificates"
        );
        anyhow::ensure!(
            parsed_ca.public_key().raw == ca_key.public_key_der(),
            "relay TLS CA certificate and private key do not match"
        );
        let ca = CertificateParams::from_ca_cert_pem(&cert_pem)
            .context("parse relay TLS CA certificate PEM")?
            .self_signed(&ca_key)
            .context("reconstruct relay TLS CA signer")?;

        let native = rustls_native_certs::load_native_certs();
        let mut roots = RootCertStore::empty();
        let (added, ignored) = roots.add_parsable_certificates(native.certs);
        anyhow::ensure!(
            added > 0,
            "no usable native CA roots found for upstream TLS"
        );
        if !native.errors.is_empty() || ignored > 0 {
            warn!(
                load_errors = native.errors.len(),
                ignored, "ignored unusable certificates from the native CA store"
            );
        }
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
        events: Option<&FlowEventClient>,
        meta: FlowMeta<'_>,
    ) -> Result<RelayCopyReport> {
        let handshake_started = Instant::now();
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
        if let Some(events) = events {
            events.emit(
                "tls.client_hello",
                meta.flow_id,
                serde_json::json!({
                    "sni": hello.server_name(),
                    "alpn_offered": offered_alpn
                        .iter()
                        .map(|protocol| match std::str::from_utf8(protocol) {
                            Ok(protocol) => protocol.to_owned(),
                            Err(_) => format!("hex:{}", hex::encode(protocol)),
                        })
                        .collect::<Vec<_>>(),
                    "min_version": null,
                    "max_version": null,
                    "parser_status": "parsed_versions_unavailable"
                }),
            )?;
        }

        let name = ServerName::try_from(server_name.clone())
            .with_context(|| format!("invalid TLS server name `{server_name}`"))?;
        let connector = TlsConnector::from(self.client_config.clone());
        let mut upstream = connector
            .with_alpn(offered_alpn)
            .connect(name, remote)
            .await
            .with_context(|| format!("verify upstream TLS certificate for {server_name}"))?;
        let selected_alpn = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let version = upstream
            .get_ref()
            .1
            .protocol_version()
            .map_or_else(|| "unknown".into(), |value| format!("{value:?}"));
        let cipher = upstream
            .get_ref()
            .1
            .negotiated_cipher_suite()
            .map_or_else(|| "unknown".into(), |value| format!("{:?}", value.suite()));
        let alpn = selected_alpn
            .as_deref()
            .map(|value| String::from_utf8_lossy(value).into_owned());

        let server_config = self.server_config(&server_name, selected_alpn)?;
        let mut downstream = start
            .into_stream(Arc::new(server_config))
            .await
            .with_context(|| format!("complete intercepted TLS handshake for {server_name}"))?;
        let latency_us = u64::try_from(handshake_started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let (client_to_remote_bytes, remote_to_client_bytes) =
            capture::copy_tcp(&mut downstream, &mut upstream, capture.open(meta).await?).await?;
        Ok(RelayCopyReport {
            client_to_remote_bytes,
            remote_to_client_bytes,
            server_name,
            version,
            cipher,
            alpn,
            latency_us,
        })
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
    let deadline = Instant::now() + CLASSIFY_TIMEOUT;
    loop {
        let read = stream.peek(&mut header).await.context("peek TCP payload")?;
        if read == 0 {
            return Ok(false);
        }
        if read >= header.len() {
            return Ok(header[0] == 0x16
                && header[1] == 0x03
                && matches!(header[2], 0x01..=0x04)
                && header[5] == 0x01);
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(false);
        }
        // Why: readiness remains asserted while the same partial bytes are
        // waiting in the socket, so another immediate peek would busy-loop.
        tokio::time::sleep(Duration::from_millis(1).min(deadline - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use heimdall_config::{CaptureConfig, CaptureMode};
    use rcgen::{BasicConstraints, IsCa};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpListener,
    };
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
        let relay_tls = RelayTls {
            ca,
            ca_key,
            client_config: Arc::new(client_config.clone()),
        };
        let server_config = relay_tls
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

    #[tokio::test]
    async fn fragmented_client_hello_is_classified_as_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let writer = tokio::spawn(async move {
            let mut stream = TcpStream::connect(address).await.unwrap();
            stream.write_all(&[0x16, 0x03, 0x03]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            stream.write_all(&[0x00, 0x01, 0x01]).await.unwrap();
        });
        let (stream, _) = listener.accept().await.unwrap();
        assert!(looks_like_client_hello(&stream).await.unwrap());
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn intercepts_verified_upstream_and_captures_plaintext() {
        let upstream_ca_key = KeyPair::generate().unwrap();
        let mut upstream_ca_params = CertificateParams::default();
        upstream_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let upstream_ca = upstream_ca_params.self_signed(&upstream_ca_key).unwrap();
        let upstream_key = KeyPair::generate().unwrap();
        let upstream_cert = CertificateParams::new(vec!["fixture.test".to_owned()])
            .unwrap()
            .signed_by(&upstream_key, &upstream_ca, &upstream_ca_key)
            .unwrap();
        let upstream_server = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(upstream_cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(upstream_key.serialize_der())),
            )
            .unwrap();

        let relay_ca_key = KeyPair::generate().unwrap();
        let mut relay_ca_params = CertificateParams::default();
        relay_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let relay_ca = relay_ca_params.self_signed(&relay_ca_key).unwrap();
        let relay_ca_der = CertificateDer::from(relay_ca.der().to_vec());
        let mut upstream_roots = RootCertStore::empty();
        upstream_roots
            .add(CertificateDer::from(upstream_ca.der().to_vec()))
            .unwrap();
        let relay_tls = RelayTls {
            ca: relay_ca,
            ca_key: relay_ca_key,
            client_config: Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(upstream_roots)
                    .with_no_client_auth(),
            ),
        };

        let capture = CaptureManager::from_config(
            &CaptureConfig {
                mode: CaptureMode::On,
                max_bytes_per_flow: 1024,
                ..CaptureConfig::default()
            },
            None,
        )
        .await
        .unwrap()
        .unwrap();

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let mut tls = TlsAcceptor::from(Arc::new(upstream_server))
                .accept(stream)
                .await
                .unwrap();
            let mut request = [0u8; 4];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.shutdown().await.unwrap();
        });

        let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay_listener.local_addr().unwrap();
        let relay_task = tokio::spawn(async move {
            let (mut downstream, _) = relay_listener.accept().await.unwrap();
            let mut upstream = TcpStream::connect(upstream_address).await.unwrap();
            relay_tls
                .copy(
                    &mut downstream,
                    &mut upstream,
                    "fixture.test",
                    &capture,
                    None,
                    FlowMeta {
                        flow_id: uuid::Uuid::now_v7(),
                        boundary: "tls_plaintext.relay",
                        network: "tcp",
                        cgroup_id: 42,
                        policy: "test",
                        destination: "fixture.test",
                        destination_port: 443,
                        action: "direct",
                        payload: "tls_plaintext",
                    },
                )
                .await
                .unwrap()
        });

        let mut client_roots = RootCertStore::empty();
        client_roots.add(relay_ca_der).unwrap();
        let client = TcpStream::connect(relay_address).await.unwrap();
        let mut tls = TlsConnector::from(Arc::new(
            ClientConfig::builder()
                .with_root_certificates(client_roots)
                .with_no_client_auth(),
        ))
        .connect(ServerName::try_from("fixture.test").unwrap(), client)
        .await
        .unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        tls.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"pong");
        tls.shutdown().await.unwrap();
        drop(tls);

        upstream_task.await.unwrap();
        let report = relay_task.await.unwrap();
        assert_eq!(
            (report.client_to_remote_bytes, report.remote_to_client_bytes),
            (4, 4)
        );
        assert_eq!(report.server_name, "fixture.test");
        assert_ne!(report.version, "unknown");
        assert_ne!(report.cipher, "unknown");
    }
}
