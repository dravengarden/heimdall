//! Cooperative explicit-proxy frontend used by the macOS CLI backend.
//!
//! The listener is deliberately loopback-only and SOCKS5 CONNECT-only. It
//! cannot prove that the wrapped command honored the injected environment, so
//! its evidence names the cooperative scope instead of borrowing Linux cgroup
//! attribution.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

use crate::{
    event_log::{EventClient, FlowEventClient},
    heimdall_config::{
        Action, CaptureMode, DecryptMode, DnsMode, HeimdallConfig, ProxyPolicy, RejectMethod,
    },
    relay_transport::{
        Dst, SOCKS5_HANDSHAKE_TIMEOUT, Upstream, open_socks5_tunnel_with_timeouts, resolve_all,
        valid_socks5_domain,
    },
};

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_NO_AUTH: u8 = 0x00;
const SOCKS5_NO_ACCEPTABLE_AUTH: u8 = 0xff;
const SOCKS5_CONNECT: u8 = 0x01;
const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REPLY_NOT_ALLOWED: u8 = 0x02;
const SOCKS5_REPLY_CONNECTION_REFUSED: u8 = 0x05;
const SOCKS5_REPLY_COMMAND_UNSUPPORTED: u8 = 0x07;
const SOCKS5_REPLY_ADDRESS_UNSUPPORTED: u8 = 0x08;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ExplicitDiagnostic {
    pub(crate) code: String,
    pub(crate) path: String,
    pub(crate) message: String,
    pub(crate) hint: String,
}

impl ExplicitDiagnostic {
    fn new(code: &str, path: impl Into<String>, message: &str, hint: &str) -> Self {
        Self {
            code: code.into(),
            path: path.into(),
            message: message.into(),
            hint: hint.into(),
        }
    }
}

/// Return every reason the selected policy cannot run in cooperative mode.
pub(crate) fn diagnostics(config: &HeimdallConfig, policy_name: &str) -> Vec<ExplicitDiagnostic> {
    let mut values = Vec::new();
    if !native_arch_supported() {
        values.push(ExplicitDiagnostic::new(
            "macos_explicit_architecture_unavailable",
            "$.platform.architecture",
            "macos-explicit has native acceptance only on Apple silicon",
            "Use an aarch64 macOS host or a supported Linux package.",
        ));
    }
    let Some(policy) = config.policy(policy_name) else {
        values.push(ExplicitDiagnostic::new(
            "unknown_policy",
            "$.cli.policy",
            "the requested policy is not declared",
            "Select one of the policy names reported by `heimdall agent`.",
        ));
        return values;
    };

    if policy.dns.mode != DnsMode::System {
        values.push(ExplicitDiagnostic::new(
            "macos_explicit_fake_dns_unavailable",
            format!("$.proxy.policies.{policy_name}.dns.mode"),
            "macos-explicit does not provide fake DNS",
            "Use dns.mode = \"system\"; SOCKS-aware clients can still send hostnames to the loopback listener.",
        ));
    }
    if !policy.rejects_all_udp() {
        values.push(ExplicitDiagnostic::new(
            "macos_explicit_udp_unavailable",
            format!("$.proxy.policies.{policy_name}.final.udp"),
            "macos-explicit accepts SOCKS5 CONNECT only and cannot route UDP",
            "Reject every UDP path in the selected policy or use the future transparent backend.",
        ));
    }
    if config.capture.mode != CaptureMode::Off {
        values.push(ExplicitDiagnostic::new(
            "macos_explicit_payload_capture_unavailable",
            "$.capture.mode",
            "macos-explicit records TCP metadata but does not capture payload bytes",
            "Set capture.mode = \"off\" for this backend.",
        ));
    }
    if config.decrypt.mode != DecryptMode::Off {
        values.push(ExplicitDiagnostic::new(
            "macos_explicit_tls_inspection_unavailable",
            "$.decrypt.mode",
            "macos-explicit cannot inspect TLS",
            "Set decrypt.mode = \"off\"; runtime TLS is unavailable on macOS and relay TLS belongs to a later transparent milestone.",
        ));
    }
    values
}

pub(crate) const fn native_arch_supported() -> bool {
    #[cfg(target_os = "macos")]
    {
        cfg!(target_arch = "aarch64")
    }
    #[cfg(not(target_os = "macos"))]
    {
        // Linux unit tests exercise the portable Apple-silicon contract.
        true
    }
}

pub(crate) fn outbound_diagnostic(config: &HeimdallConfig) -> Option<ExplicitDiagnostic> {
    resolve_all(config).err().map(|error| {
        ExplicitDiagnostic::new(
            "macos_explicit_outbound_unavailable",
            "$.proxy.outbounds",
            &format!("cannot prepare the configured SOCKS5 outbounds: {error:#}"),
            "Make every selected password_file readable and verify the upstream address.",
        )
    })
}

pub(crate) struct ExplicitProxy {
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<Result<()>>>,
}

impl ExplicitProxy {
    pub(crate) async fn start(
        config: &HeimdallConfig,
        policy_name: &str,
        events: EventClient,
    ) -> Result<Self> {
        let diagnostics = diagnostics(config, policy_name);
        anyhow::ensure!(
            diagnostics.is_empty(),
            "{}: {}",
            diagnostics[0].code,
            diagnostics[0].message
        );
        let policy = Arc::new(
            config
                .policy(policy_name)
                .expect("explicit diagnostics resolved the policy")
                .clone(),
        );
        let upstreams = Arc::new(resolve_all(config)?);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind macos-explicit loopback SOCKS5 listener")?;
        let address = listener.local_addr()?;
        let (shutdown, receiver) = watch::channel(false);
        let policy_name = policy_name.to_owned();
        let task = tokio::spawn(serve(
            listener,
            receiver,
            policy_name,
            policy,
            upstreams,
            events,
        ));
        Ok(Self {
            address,
            shutdown,
            task: Some(task),
        })
    }

    pub(crate) fn proxy_url(&self) -> String {
        format!("socks5h://{}", self.address)
    }

    pub(crate) async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown.send(true);
        self.task
            .take()
            .expect("macos-explicit listener joins once")
            .await
            .context("join macos-explicit listener")??;
        Ok(())
    }
}

impl Drop for ExplicitProxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn serve(
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
    policy_name: String,
    policy: Arc<ProxyPolicy>,
    upstreams: Arc<HashMap<String, Arc<Upstream>>>,
    events: EventClient,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                let _ = changed;
                break;
            }
            accepted = listener.accept() => {
                let (client, _) = accepted.context("accept macos-explicit SOCKS5 client")?;
                let policy_name = policy_name.clone();
                let policy = Arc::clone(&policy);
                let upstreams = Arc::clone(&upstreams);
                let events = events.clone();
                connections.spawn(async move {
                    if let Err(error) = handle_client(client, &policy_name, &policy, &upstreams, &events).await {
                        eprintln!("heimdall run: macos-explicit client failed: {error:#}");
                    }
                });
            }
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    eprintln!("heimdall run: macos-explicit client task failed: {error}");
                }
            }
        }
    }

    // Why: a descendant can retain the inherited proxy environment after the
    // immediate child exits. Closing every accepted stream here keeps the
    // listener strictly foreground-owned without claiming descendant cleanup.
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}

async fn handle_client(
    mut client: TcpStream,
    policy_name: &str,
    policy: &ProxyPolicy,
    upstreams: &HashMap<String, Arc<Upstream>>,
    events: &EventClient,
) -> Result<()> {
    tokio::time::timeout(
        SOCKS5_HANDSHAKE_TIMEOUT,
        handle_client_inner(&mut client, policy_name, policy, upstreams, events),
    )
    .await
    .context("macos-explicit client handshake timed out")?
}

async fn handle_client_inner(
    client: &mut TcpStream,
    policy_name: &str,
    policy: &ProxyPolicy,
    upstreams: &HashMap<String, Arc<Upstream>>,
    events: &EventClient,
) -> Result<()> {
    negotiate_client(client).await?;
    let (command, destination, port) = read_request(client).await?;
    if command != SOCKS5_CONNECT {
        write_reply(client, SOCKS5_REPLY_COMMAND_UNSUPPORTED, None).await?;
        return Ok(());
    }
    if port == 0 {
        write_reply(client, SOCKS5_REPLY_ADDRESS_UNSUPPORTED, None).await?;
        return Ok(());
    }

    let (domain, ip) = match &destination {
        Dst::Domain(host) => (Some(host.as_str()), None),
        Dst::Ip4(value) => (None, Some(IpAddr::V4(*value))),
        Dst::Ip6(value) => (None, Some(IpAddr::V6(*value))),
    };
    let destination_value = destination_json(&destination, port);
    let (rule, action) = policy.explain_tcp(domain, ip, port);
    let action = action.clone();
    events.emit_run(
        "policy.decision",
        json!({
            "source": explicit_source(),
            "policy": policy_name,
            "network": "tcp",
            "destination": destination_value,
            "rule": {
                "name": rule.map(|value| value.name.as_str()),
                "source": if rule.is_some() { "ordered_rule" } else { "final" }
            },
            "action": action_json(&action)
        }),
    )?;

    let mut remote = match &action {
        Action::Route { outbound } => {
            let Some(upstream) = upstreams.get(outbound) else {
                write_reply(client, SOCKS5_REPLY_GENERAL_FAILURE, None).await?;
                anyhow::bail!("selected outbound `{outbound}` was not prepared");
            };
            let Upstream::Socks5 {
                addr,
                auth,
                connect_timeout,
            } = upstream.as_ref();
            match open_socks5_tunnel_with_timeouts(
                addr,
                &destination,
                port,
                auth.as_ref(),
                *connect_timeout,
                SOCKS5_HANDSHAKE_TIMEOUT,
            )
            .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    write_reply(client, SOCKS5_REPLY_CONNECTION_REFUSED, None).await?;
                    return Err(error.context("open selected SOCKS5 outbound"));
                }
            }
        }
        Action::Direct => match connect_direct(&destination, port).await {
            Ok(stream) => stream,
            Err(error) => {
                write_reply(client, SOCKS5_REPLY_CONNECTION_REFUSED, None).await?;
                return Err(error);
            }
        },
        Action::Reject { .. } => {
            write_reply(client, SOCKS5_REPLY_NOT_ALLOWED, None).await?;
            return Ok(());
        }
    };

    let flow_id = uuid::Uuid::now_v7();
    let flow_events = events.start_flow();
    flow_events.emit(
        "flow.open",
        flow_id,
        json!({
            "network": "tcp",
            "source": explicit_source(),
            "destination": destination_json(&destination, port),
            "action": action_json(&action),
            "policy": policy_name,
            "boundary": "transport"
        }),
    )?;
    let flow = FlowEvidence::new(flow_events, flow_id);
    write_reply(client, SOCKS5_REPLY_SUCCEEDED, remote.local_addr().ok()).await?;

    match copy_bidirectional(client, &mut remote).await {
        Ok((client_to_remote, remote_to_client)) => {
            flow.close("complete", None, client_to_remote, remote_to_client)
        }
        Err(error) => {
            let close = flow.close("error", Some("relay_failed"), 0, 0);
            if let Err(close_error) = close {
                eprintln!(
                    "heimdall run: cannot close macos-explicit flow evidence: {close_error:#}"
                );
            }
            Err(error).context("copy macos-explicit TCP stream")
        }
    }
}

async fn negotiate_client(client: &mut TcpStream) -> Result<()> {
    let mut header = [0u8; 2];
    client.read_exact(&mut header).await?;
    anyhow::ensure!(
        header[0] == SOCKS5_VERSION,
        "SOCKS5 client used an unsupported version"
    );
    anyhow::ensure!(
        header[1] != 0,
        "SOCKS5 client offered no authentication methods"
    );
    let mut methods = vec![0u8; header[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&SOCKS5_NO_AUTH) {
        client
            .write_all(&[SOCKS5_VERSION, SOCKS5_NO_ACCEPTABLE_AUTH])
            .await?;
        anyhow::bail!("SOCKS5 client did not offer no-authentication mode");
    }
    client.write_all(&[SOCKS5_VERSION, SOCKS5_NO_AUTH]).await?;
    Ok(())
}

async fn read_request(client: &mut TcpStream) -> Result<(u8, Dst, u16)> {
    let mut header = [0u8; 4];
    client.read_exact(&mut header).await?;
    anyhow::ensure!(
        header[0] == SOCKS5_VERSION,
        "SOCKS5 request used an unsupported version"
    );
    anyhow::ensure!(
        header[2] == 0,
        "SOCKS5 request has a non-zero reserved byte"
    );
    let destination = match header[3] {
        0x01 => {
            let mut raw = [0u8; 4];
            client.read_exact(&mut raw).await?;
            Dst::Ip4(raw.into())
        }
        0x04 => {
            let mut raw = [0u8; 16];
            client.read_exact(&mut raw).await?;
            Dst::Ip6(raw.into())
        }
        0x03 => {
            let mut raw_length = [0u8; 1];
            client.read_exact(&mut raw_length).await?;
            anyhow::ensure!(raw_length[0] != 0, "SOCKS5 destination domain is empty");
            let mut raw = vec![0u8; raw_length[0] as usize];
            client.read_exact(&mut raw).await?;
            let host =
                std::str::from_utf8(&raw).context("SOCKS5 destination domain is not UTF-8")?;
            if !valid_socks5_domain(host) {
                write_reply(client, SOCKS5_REPLY_ADDRESS_UNSUPPORTED, None).await?;
                anyhow::bail!("SOCKS5 destination domain is invalid");
            }
            Dst::Domain(host.to_owned())
        }
        _ => {
            write_reply(client, SOCKS5_REPLY_ADDRESS_UNSUPPORTED, None).await?;
            anyhow::bail!("SOCKS5 request used an unsupported address type");
        }
    };
    let mut raw_port = [0u8; 2];
    client.read_exact(&mut raw_port).await?;
    let port = u16::from_be_bytes(raw_port);
    Ok((header[1], destination, port))
}

async fn connect_direct(destination: &Dst, port: u16) -> Result<TcpStream> {
    match destination {
        Dst::Ip4(ip) => TcpStream::connect(SocketAddr::new((*ip).into(), port)).await,
        Dst::Ip6(ip) => TcpStream::connect(SocketAddr::new((*ip).into(), port)).await,
        Dst::Domain(host) => TcpStream::connect((host.as_str(), port)).await,
    }
    .with_context(|| format!("direct CONNECT {}:{port}", destination_label(destination)))
}

async fn write_reply(client: &mut TcpStream, reply: u8, bound: Option<SocketAddr>) -> Result<()> {
    let bound = bound.unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    let mut response = vec![SOCKS5_VERSION, reply, 0];
    match bound.ip() {
        IpAddr::V4(ip) => {
            response.push(0x01);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(0x04);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&bound.port().to_be_bytes());
    client
        .write_all(&response)
        .await
        .context("write SOCKS5 reply")
}

fn explicit_source() -> Value {
    json!({
        "backend": "macos-explicit",
        "scope": "cooperative_environment"
    })
}

fn destination_json(destination: &Dst, port: u16) -> Value {
    match destination {
        Dst::Ip4(ip) => json!({"ip": ip, "port": port}),
        Dst::Ip6(ip) => json!({"ip": ip, "port": port}),
        Dst::Domain(host) => json!({"host": host, "port": port}),
    }
}

fn destination_label(destination: &Dst) -> String {
    match destination {
        Dst::Ip4(ip) => ip.to_string(),
        Dst::Ip6(ip) => ip.to_string(),
        Dst::Domain(host) => host.clone(),
    }
}

fn action_json(action: &Action) -> Value {
    match action {
        Action::Route { outbound } => json!({"type": "route", "outbound": outbound}),
        Action::Direct => json!({"type": "direct"}),
        Action::Reject { method } => json!({
            "type": "reject",
            "method": match method {
                RejectMethod::Refused => "refused",
            }
        }),
    }
}

struct FlowEvidence {
    events: Option<FlowEventClient>,
    flow_id: uuid::Uuid,
    started: Instant,
}

impl FlowEvidence {
    fn new(events: FlowEventClient, flow_id: uuid::Uuid) -> Self {
        Self {
            events: Some(events),
            flow_id,
            started: Instant::now(),
        }
    }

    fn close(
        mut self,
        status: &str,
        error_code: Option<&str>,
        client_to_remote_bytes: u64,
        remote_to_client_bytes: u64,
    ) -> Result<()> {
        let events = self.events.take().expect("flow evidence closes once");
        events.emit(
            "flow.close",
            self.flow_id,
            json!({
                "network": "tcp",
                "status": status,
                "error_code": error_code,
                "client_to_remote_bytes": client_to_remote_bytes,
                "remote_to_client_bytes": remote_to_client_bytes,
                "duration_us": elapsed_us(self.started)
            }),
        )
    }
}

impl Drop for FlowEvidence {
    fn drop(&mut self) {
        let Some(events) = self.events.take() else {
            return;
        };
        let _ = events.emit(
            "flow.close",
            self.flow_id,
            json!({
                "network": "tcp",
                "status": "interrupted",
                "error_code": "run_completed",
                "client_to_remote_bytes": 0,
                "remote_to_client_bytes": 0,
                "duration_us": elapsed_us(self.started)
            }),
        );
    }
}

fn elapsed_us(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tokio::net::TcpListener;

    use super::*;
    use crate::{
        event_log::{RotationServer, RunLog, read_manifest},
        heimdall_config::HeimdallConfig,
    };

    fn config_with_upstream(port: u16) -> HeimdallConfig {
        let source = crate::cli::init::InitFormat::Toml
            .template()
            .replace("server_port = 1080", &format!("server_port = {port}"))
            .replace("mode = \"fake\"", "mode = \"system\"");
        let config: HeimdallConfig = toml::from_str(&source).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn reduced_mode_preflight_rejects_unavailable_capabilities() {
        let source = crate::cli::init::InitFormat::Toml.template();
        let mut config: HeimdallConfig = toml::from_str(source).unwrap();
        config.validate().unwrap();
        config.capture.mode = CaptureMode::On;
        config.decrypt.mode = DecryptMode::Runtime;
        let diagnostics = diagnostics(&config, "default");
        let codes = diagnostics
            .iter()
            .map(|value| value.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"macos_explicit_fake_dns_unavailable"));
        assert!(codes.contains(&"macos_explicit_payload_capture_unavailable"));
        assert!(codes.contains(&"macos_explicit_tls_inspection_unavailable"));
    }

    #[tokio::test]
    async fn loopback_frontend_routes_tcp_and_records_cooperative_source() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0u8; 18];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[5..16], b"example.com");
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let uuid = uuid::Uuid::now_v7().simple().to_string();
        let root = Path::new("/tmp").join(format!("hx-{}-{}", std::process::id(), &uuid[..8]));
        let runtime = root.join("runtime");
        let log =
            RunLog::create_at(&root, &["client".into()], "default", "macos-explicit").unwrap();
        let server = RotationServer::start_at(log.clone(), &runtime).unwrap();
        let events = EventClient::connect(server.event_socket_path().to_path_buf()).unwrap();
        let config = config_with_upstream(upstream_port);
        let proxy = ExplicitProxy::start(&config, "default", events)
            .await
            .unwrap();

        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 0]);
        let host = b"example.com";
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], SOCKS5_REPLY_SUCCEEDED);
        client.write_all(b"ping").await.unwrap();
        let mut response = [0u8; 4];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        drop(client);
        upstream_task.await.unwrap();
        proxy.shutdown().await.unwrap();
        drop(server);
        log.finish(0, false).unwrap();

        let run_dir = log.run_dir().unwrap();
        let manifest = read_manifest(&run_dir.join("run.json")).unwrap();
        assert_eq!(manifest.backend, "macos-explicit");
        assert!(!manifest.result.unwrap().complete);
        let events = std::fs::read_to_string(run_dir.join("events-000001.jsonl")).unwrap();
        assert!(events.lines().any(|line| {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            value["data"]["source"]["backend"] == "macos-explicit"
                && value["data"]["source"]["scope"] == "cooperative_environment"
        }));
        assert!(events.contains(r#""kind":"flow.close""#));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn frontend_rejects_udp_associate_without_contacting_upstream() {
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let uuid = uuid::Uuid::now_v7().simple().to_string();
        let root = Path::new("/tmp").join(format!("hu-{}-{}", std::process::id(), &uuid[..8]));
        let runtime = root.join("runtime");
        let log =
            RunLog::create_at(&root, &["client".into()], "default", "macos-explicit").unwrap();
        let server = RotationServer::start_at(log.clone(), &runtime).unwrap();
        let events = EventClient::connect(server.event_socket_path().to_path_buf()).unwrap();
        let config = config_with_upstream(upstream_port);
        let proxy = ExplicitProxy::start(&config, "default", events)
            .await
            .unwrap();

        let mut client = TcpStream::connect(proxy.address).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut greeting = [0u8; 2];
        client.read_exact(&mut greeting).await.unwrap();
        client
            .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], SOCKS5_REPLY_COMMAND_UNSUPPORTED);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), upstream.accept())
                .await
                .is_err()
        );

        proxy.shutdown().await.unwrap();
        drop(server);
        log.finish(0, false).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
