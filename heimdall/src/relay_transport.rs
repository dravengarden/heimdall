//! Platform-neutral outbound transport for the foreground relay.
//!
//! Interception and original-destination correlation remain backend-owned.
//! This module owns the reusable SOCKS5 TCP/UDP protocol, credential
//! resolution, destination encoding, and bounded connection setup needed by
//! both the Linux relay and future Darwin backends.

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use tokio::net::{TcpStream, UdpSocket};

use crate::heimdall_config::{HeimdallConfig, Outbound, Socks5Auth, Socks5Outbound};

#[derive(Clone, Debug)]
pub(crate) enum Upstream {
    Socks5 {
        addr: String,
        auth: Option<ResolvedAuth>,
        connect_timeout: Duration,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedAuth {
    username: String,
    password: Vec<u8>,
}

impl Upstream {
    fn from_outbound(outbound: &Outbound) -> Result<Self> {
        match outbound {
            Outbound::Socks5(Socks5Outbound {
                auth,
                connect_timeout,
                ..
            }) => {
                let resolved = auth.as_ref().map(resolve_auth).transpose()?;
                Ok(Self::Socks5 {
                    addr: outbound_address(outbound),
                    auth: resolved,
                    connect_timeout: parse_timeout(connect_timeout),
                })
            }
        }
    }
}

fn resolve_auth(auth: &Socks5Auth) -> Result<ResolvedAuth> {
    let password = auth
        .read_password()
        .with_context(|| format!("read password file {}", auth.password_file.display()))?;
    anyhow::ensure!(
        (1..=255).contains(&password.len()),
        "SOCKS5 password must contain 1..=255 bytes after trimming one trailing newline"
    );
    Ok(ResolvedAuth {
        username: auth.username.clone(),
        password,
    })
}

/// Resolve every outbound once so connection handling never rereads secrets.
pub(crate) fn resolve_all(cfg: &HeimdallConfig) -> Result<HashMap<String, Arc<Upstream>>> {
    let mut out = HashMap::with_capacity(cfg.proxy.outbounds.len());
    for (name, outbound) in &cfg.proxy.outbounds {
        let upstream = Upstream::from_outbound(outbound)
            .with_context(|| format!("resolving outbound `{name}`"))?;
        out.insert(name.clone(), Arc::new(upstream));
    }
    Ok(out)
}

fn outbound_address(outbound: &Outbound) -> String {
    match outbound {
        Outbound::Socks5(socks) => socks.address(),
    }
}

fn parse_timeout(value: &str) -> Duration {
    let (raw, multiplier) = value
        .strip_suffix("ms")
        .map(|raw| (raw, 1))
        .or_else(|| value.strip_suffix('s').map(|raw| (raw, 1_000)))
        .or_else(|| value.strip_suffix('m').map(|raw| (raw, 60_000)))
        .expect("strict config validation accepted connect_timeout");
    Duration::from_millis(
        raw.parse::<u64>()
            .expect("strict config validation accepted duration digits")
            * multiplier,
    )
}

/// SOCKS5 destination encoded as an address literal or hostname.
#[derive(Debug, Clone)]
pub(crate) enum Dst {
    Ip4(Ipv4Addr),
    Ip6(Ipv6Addr),
    Domain(String),
}

pub(crate) async fn destination_socket_addr(dst: &Dst, port: u16) -> Result<SocketAddr> {
    match dst {
        Dst::Ip4(ip) => Ok(SocketAddr::new((*ip).into(), port)),
        Dst::Ip6(ip) => Ok(SocketAddr::new((*ip).into(), port)),
        Dst::Domain(domain) => tokio::net::lookup_host((domain.as_str(), port))
            .await
            .with_context(|| format!("resolve UDP destination {domain}:{port}"))?
            .next()
            .with_context(|| format!("no address for UDP destination {domain}:{port}")),
    }
}

const M_NO_AUTH: u8 = 0x00;
const M_USER_PASS: u8 = 0x02;
const M_NO_ACCEPTABLE: u8 = 0xFF;
pub(crate) const SOCKS5_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const SOCKS5_UDP_MAX_PAYLOAD: usize = 65_245;

pub(crate) async fn open_socks5_udp_association(
    upstream: &Upstream,
) -> Result<(TcpStream, UdpSocket)> {
    let Upstream::Socks5 {
        addr,
        auth,
        connect_timeout,
    } = upstream;
    let mut control = tokio::time::timeout(*connect_timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to SOCKS5 {addr}"))?
        .with_context(|| format!("connect to SOCKS5 {addr}"))?;
    let relay_addr = tokio::time::timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        socks5_udp_associate(&mut control, auth.as_ref()),
    )
    .await
    .with_context(|| format!("timed out negotiating SOCKS5 UDP with {addr}"))??;
    let relay_addr = if relay_addr.ip().is_unspecified() {
        SocketAddr::new(control.peer_addr()?.ip(), relay_addr.port())
    } else {
        relay_addr
    };
    let bind = if relay_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("bind SOCKS5 UDP socket")?;
    socket
        .connect(relay_addr)
        .await
        .with_context(|| format!("connect SOCKS5 UDP relay {relay_addr}"))?;
    Ok((control, socket))
}

async fn socks5_udp_associate(
    stream: &mut TcpStream,
    auth: Option<&ResolvedAuth>,
) -> Result<SocketAddr> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    socks5_negotiate(stream, auth).await?;
    stream
        .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    anyhow::ensure!(header[0] == 5, "SOCKS5: bad UDP ASSOCIATE version");
    anyhow::ensure!(
        header[1] == 0,
        "SOCKS5 UDP ASSOCIATE rejected: code=0x{:02x}",
        header[1]
    );
    anyhow::ensure!(header[2] == 0, "SOCKS5: non-zero reserved reply byte");
    read_socks5_socket_addr(stream, header[3]).await
}

async fn socks5_negotiate(stream: &mut TcpStream, auth: Option<&ResolvedAuth>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let methods: &[u8] = if auth.is_some() {
        &[M_USER_PASS]
    } else {
        &[M_NO_AUTH]
    };
    stream.write_all(&[5, methods.len() as u8]).await?;
    stream.write_all(methods).await?;
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await?;
    anyhow::ensure!(selected[0] == 5, "SOCKS5: bad method reply version");
    match (selected[1], auth) {
        (M_NO_AUTH, None) => Ok(()),
        (M_USER_PASS, Some(auth)) => socks5_userpass(stream, &auth.username, &auth.password).await,
        (M_NO_ACCEPTABLE, _) => anyhow::bail!("SOCKS5: server rejected all offered methods"),
        (method, _) => anyhow::bail!(
            "SOCKS5: server selected method 0x{method:02x} that the client did not offer"
        ),
    }
}

async fn read_socks5_socket_addr(stream: &mut TcpStream, atyp: u8) -> Result<SocketAddr> {
    use tokio::io::AsyncReadExt;

    let host = match atyp {
        1 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            Dst::Ip4(Ipv4Addr::from(raw))
        }
        4 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            Dst::Ip6(Ipv6Addr::from(raw))
        }
        3 => {
            let mut raw_len = [0u8; 1];
            stream.read_exact(&mut raw_len).await?;
            anyhow::ensure!(raw_len[0] != 0, "SOCKS5 UDP relay domain is empty");
            let mut raw = vec![0u8; raw_len[0] as usize];
            stream.read_exact(&mut raw).await?;
            let domain =
                std::str::from_utf8(&raw).context("SOCKS5 UDP relay domain is not UTF-8")?;
            anyhow::ensure!(
                valid_socks5_domain(domain),
                "SOCKS5 UDP relay domain is invalid"
            );
            Dst::Domain(domain.to_owned())
        }
        other => anyhow::bail!("SOCKS5: unknown reply ATYP 0x{other:02x}"),
    };
    let mut raw_port = [0u8; 2];
    stream.read_exact(&mut raw_port).await?;
    let port = u16::from_be_bytes(raw_port);
    anyhow::ensure!(port != 0, "SOCKS5 UDP relay returned port zero");
    destination_socket_addr(&host, port).await
}

fn encode_socks5_destination(output: &mut Vec<u8>, dst: &Dst, port: u16) -> Result<()> {
    match dst {
        Dst::Ip4(ip) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Dst::Ip6(ip) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        Dst::Domain(host) => {
            anyhow::ensure!(
                (1..=255).contains(&host.len()),
                "SOCKS5: invalid domain length"
            );
            anyhow::ensure!(valid_socks5_domain(host), "SOCKS5: invalid domain name");
            output.push(3);
            output.push(host.len() as u8);
            output.extend_from_slice(host.as_bytes());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

pub(crate) fn encode_socks5_udp_frame(dst: &Dst, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    anyhow::ensure!(
        payload.len() <= SOCKS5_UDP_MAX_PAYLOAD,
        "SOCKS5 UDP payload exceeds {SOCKS5_UDP_MAX_PAYLOAD} bytes"
    );
    let mut frame = Vec::with_capacity(payload.len() + 262);
    frame.extend_from_slice(&[0, 0, 0]);
    encode_socks5_destination(&mut frame, dst, port)?;
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub(crate) fn decode_socks5_udp_payload(frame: &[u8]) -> Result<&[u8]> {
    anyhow::ensure!(frame.len() >= 4, "SOCKS5 UDP response is truncated");
    anyhow::ensure!(
        frame[0..2] == [0, 0],
        "SOCKS5 UDP response has non-zero RSV"
    );
    anyhow::ensure!(
        frame[2] == 0,
        "fragmented SOCKS5 UDP responses are unsupported"
    );
    let address_len = match frame[3] {
        1 => 4,
        4 => 16,
        3 => {
            anyhow::ensure!(frame.len() >= 5, "SOCKS5 UDP domain response is truncated");
            1 + frame[4] as usize
        }
        other => anyhow::bail!("SOCKS5 UDP response has unknown ATYP 0x{other:02x}"),
    };
    let payload_offset = 4 + address_len + 2;
    anyhow::ensure!(
        frame.len() >= payload_offset,
        "SOCKS5 UDP response is truncated"
    );
    Ok(&frame[payload_offset..])
}

pub(crate) async fn open_socks5_tunnel_with_timeouts(
    addr: &str,
    dst: &Dst,
    port: u16,
    auth: Option<&ResolvedAuth>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<TcpStream> {
    let mut stream = tokio::time::timeout(connect_timeout, TcpStream::connect(addr))
        .await
        .with_context(|| format!("timed out connecting to SOCKS5 {addr}"))?
        .with_context(|| format!("connect to SOCKS5 {addr}"))?;
    tokio::time::timeout(
        handshake_timeout,
        socks5_connect(&mut stream, dst, port, auth),
    )
    .await
    .with_context(|| format!("timed out negotiating SOCKS5 with {addr}"))??;
    Ok(stream)
}

async fn socks5_connect(
    stream: &mut TcpStream,
    dst: &Dst,
    port: u16,
    auth: Option<&ResolvedAuth>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let methods: &[u8] = if auth.is_some() {
        &[M_USER_PASS]
    } else {
        &[M_NO_AUTH]
    };
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;

    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await?;
    anyhow::ensure!(
        selected[0] == 0x05,
        "SOCKS5: bad version in method reply: {selected:?}"
    );

    match (selected[1], auth) {
        (M_NO_AUTH, None) => {}
        (M_USER_PASS, Some(auth)) => {
            socks5_userpass(stream, &auth.username, &auth.password).await?;
        }
        (M_NO_AUTH, Some(_)) | (M_USER_PASS, None) => {
            anyhow::bail!(
                "SOCKS5: server selected method 0x{:02x} that the client did not offer",
                selected[1]
            )
        }
        (M_NO_ACCEPTABLE, _) => anyhow::bail!("SOCKS5: server rejected all offered methods"),
        (other, _) => anyhow::bail!("SOCKS5: unsupported method 0x{other:02x}"),
    }

    let mut request = Vec::with_capacity(8 + 256);
    request.extend_from_slice(&[0x05, 0x01, 0x00]);
    encode_socks5_destination(&mut request, dst, port)?;
    stream.write_all(&request).await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    anyhow::ensure!(
        header[0] == 0x05,
        "SOCKS5: bad version in CONNECT reply: {header:?}"
    );
    anyhow::ensure!(
        header[1] == 0x00,
        "SOCKS5 CONNECT rejected by server: code=0x{:02x}",
        header[1]
    );
    anyhow::ensure!(header[2] == 0x00, "SOCKS5: non-zero reserved reply byte");
    match header[3] {
        0x01 => {
            let mut tail = [0u8; 4 + 2];
            stream.read_exact(&mut tail).await?;
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            let mut tail = vec![0u8; length[0] as usize + 2];
            stream.read_exact(&mut tail).await?;
        }
        0x04 => {
            let mut tail = [0u8; 16 + 2];
            stream.read_exact(&mut tail).await?;
        }
        other => anyhow::bail!("SOCKS5: unknown reply ATYP 0x{other:02x}"),
    }
    Ok(())
}

fn valid_socks5_domain(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.is_ascii()
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

async fn socks5_userpass(stream: &mut TcpStream, username: &str, password: &[u8]) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    anyhow::ensure!(
        (1..=255).contains(&username.len()),
        "SOCKS5 user/pass: username must contain 1..=255 bytes"
    );
    anyhow::ensure!(
        (1..=255).contains(&password.len()),
        "SOCKS5 user/pass: password must contain 1..=255 bytes"
    );

    let mut request = Vec::with_capacity(3 + username.len() + password.len());
    request.push(0x01);
    request.push(username.len() as u8);
    request.extend_from_slice(username.as_bytes());
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;

    let mut response = [0u8; 2];
    stream.read_exact(&mut response).await?;
    anyhow::ensure!(
        response[0] == 0x01,
        "SOCKS5 user/pass: bad sub-version: {response:?}"
    );
    anyhow::ensure!(
        response[1] == 0x00,
        "SOCKS5 user/pass: auth failed (status=0x{:02x})",
        response[1]
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn encodes_and_decodes_socks5_udp_frames() {
        let cases = [
            Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8)),
            Dst::Ip6("2001:db8::8".parse().unwrap()),
            Dst::Domain("internal.example.com".into()),
        ];

        for dst in cases {
            let mut frame = vec![0, 0, 0];
            encode_socks5_destination(&mut frame, &dst, 5353).unwrap();
            frame.extend_from_slice(b"payload");
            assert_eq!(decode_socks5_udp_payload(&frame).unwrap(), b"payload");
        }
        assert!(
            encode_socks5_udp_frame(
                &Dst::Domain("internal.example.com".into()),
                5353,
                &vec![0; SOCKS5_UDP_MAX_PAYLOAD + 1],
            )
            .unwrap_err()
            .to_string()
            .contains("exceeds")
        );
    }

    #[test]
    fn rejects_fragmented_or_truncated_socks5_udp_frames() {
        assert!(
            decode_socks5_udp_payload(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53])
                .unwrap_err()
                .to_string()
                .contains("fragmented")
        );
        assert!(decode_socks5_udp_payload(&[0, 0, 0, 4, 0]).is_err());
    }

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        (client.unwrap(), accepted.unwrap().0)
    }

    #[tokio::test]
    async fn udp_associate_accepts_domain_relay_and_rejects_port_zero() {
        for (port, should_succeed) in [(19000u16, true), (0, false)] {
            let (mut client, mut server) = tcp_pair().await;
            let server_task = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
                let mut request = [0u8; 10];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request[0..4], [0x05, 0x03, 0x00, 0x01]);
                let host = b"localhost";
                let mut response = vec![0x05, 0x00, 0x00, 0x03, host.len() as u8];
                response.extend_from_slice(host);
                response.extend_from_slice(&port.to_be_bytes());
                server.write_all(&response).await.unwrap();
            });

            let result = socks5_udp_associate(&mut client, None).await;
            assert_eq!(result.is_ok(), should_succeed);
            if let Ok(address) = result {
                assert_eq!(address.port(), port);
            }
            server_task.await.unwrap();
        }
    }

    fn request_bytes(dst: &Dst, port: u16) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00];
        match dst {
            Dst::Ip4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            Dst::Ip6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
            Dst::Domain(domain) => {
                request.push(0x03);
                request.push(domain.len() as u8);
                request.extend_from_slice(domain.as_bytes());
            }
        }
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    #[tokio::test]
    async fn encodes_ipv4_ipv6_and_domain_connect_requests() {
        let cases = [
            Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8)),
            Dst::Ip6("2001:db8::8".parse().unwrap()),
            Dst::Domain("internal.example.com".into()),
        ];

        for dst in cases {
            let (mut client, mut server) = tcp_pair().await;
            let expected = request_bytes(&dst, 443);
            let server_task = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [0x05, 0x01, M_NO_AUTH]);
                server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();

                let mut request = vec![0u8; expected.len()];
                server.read_exact(&mut request).await.unwrap();
                assert_eq!(request, expected);
                server
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
            });

            socks5_connect(&mut client, &dst, 443, None).await.unwrap();
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn configured_auth_cannot_downgrade_and_preserves_password_bytes() {
        let (mut client, mut server) = tcp_pair().await;
        let auth = ResolvedAuth {
            username: "alice".into(),
            password: vec![0xff, 0x00, b'p'],
        };
        let dst = Dst::Domain("example.com".into());
        let expected_request = request_bytes(&dst, 443);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, M_USER_PASS]);
            server.write_all(&[0x05, M_USER_PASS]).await.unwrap();

            let mut auth_request = [0u8; 11];
            server.read_exact(&mut auth_request).await.unwrap();
            assert_eq!(
                auth_request,
                [0x01, 5, b'a', b'l', b'i', b'c', b'e', 3, 0xff, 0x00, b'p',]
            );
            server.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = vec![0u8; expected_request.len()];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, expected_request);
            server
                .write_all(&[
                    0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0,
                ])
                .await
                .unwrap();
        });

        socks5_connect(&mut client, &dst, 443, Some(&auth))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_server_selected_auth_method_that_was_not_offered() {
        let (mut client, mut server) = tcp_pair().await;
        let auth = ResolvedAuth {
            username: "alice".into(),
            password: b"secret".to_vec(),
        };
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, M_USER_PASS]);
            server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
        });

        let error = socks5_connect(
            &mut client,
            &Dst::Domain("example.com".into()),
            443,
            Some(&auth),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("did not offer"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_nonzero_reserved_reply_byte() {
        let (mut client, mut server) = tcp_pair().await;
        let dst = Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8));
        let request_len = request_bytes(&dst, 443).len();
        let server_task = tokio::spawn(async move {
            let mut greeting = [0u8; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
            let mut request = vec![0u8; request_len];
            server.read_exact(&mut request).await.unwrap();
            server
                .write_all(&[0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
        });

        let error = socks5_connect(&mut client, &dst, 443, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reserved"));
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_empty_and_non_ascii_domains() {
        for domain in [
            String::new(),
            "例.example".into(),
            "bad host.example".into(),
            "-bad.example".into(),
        ] {
            let (mut client, mut server) = tcp_pair().await;
            let server_task = tokio::spawn(async move {
                let mut greeting = [0u8; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[0x05, M_NO_AUTH]).await.unwrap();
            });
            assert!(
                socks5_connect(&mut client, &Dst::Domain(domain), 443, None)
                    .await
                    .is_err()
            );
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn handshake_timeout_bounds_silent_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let error = open_socks5_tunnel_with_timeouts(
            &addr.to_string(),
            &Dst::Ip4(Ipv4Addr::new(203, 0, 113, 8)),
            443,
            None,
            Duration::from_secs(1),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("timed out negotiating"));
        server_task.abort();
    }
}
