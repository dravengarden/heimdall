//! Foreground-owned dynamic-call interposition backend for Linux and macOS.

use std::{
    env, fs,
    fs::OpenOptions,
    io::Write,
    os::unix::{fs::OpenOptionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde_json::json;
use tokio::process::Command;

use crate::{
    event_log::EventClient,
    explicit_proxy::{ExplicitDiagnostic, ExplicitProxy, interpose_diagnostics},
    heimdall_config::{DnsMode, HeimdallConfig},
    run_evidence::RunEvidence,
};

#[cfg(target_os = "linux")]
const LIBRARY_NAME: &str = "libheimdall_interpose.so";
#[cfg(target_os = "macos")]
const LIBRARY_NAME: &str = "libheimdall_interpose.dylib";

const ARTIFACT_KIND: &str = env!("HEIMDALL_INTERPOSE_ARTIFACT_KIND");
const LIBRARY_BYTES: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/",
    env!("HEIMDALL_INTERPOSE_LIBRARY_NAME")
));

pub(crate) fn artifact_available() -> bool {
    if ARTIFACT_KIND != "native" {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        LIBRARY_BYTES.starts_with(b"\x7fELF")
    }
    #[cfg(target_os = "macos")]
    {
        matches!(
            LIBRARY_BYTES.get(..4),
            Some([0xcf, 0xfa, 0xed, 0xfe])
                | Some([0xca, 0xfe, 0xba, 0xbe])
                | Some([0xca, 0xfe, 0xba, 0xbf])
        )
    }
}

pub(crate) const fn architecture_supported() -> bool {
    #[cfg(target_os = "macos")]
    {
        cfg!(target_arch = "aarch64")
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

pub(crate) fn diagnostics(config: &HeimdallConfig, policy_name: &str) -> Vec<ExplicitDiagnostic> {
    let mut values = interpose_diagnostics(config, policy_name);
    if !architecture_supported() {
        values.push(ExplicitDiagnostic::new(
            "interpose_architecture_unavailable",
            "$.platform.architecture",
            "interpose is available only on Apple-silicon macOS",
            "Select explicit on this macOS architecture.",
        ));
    }
    if let Err(error) = crate::relay_transport::resolve_all(config) {
        values.push(ExplicitDiagnostic::new(
            "interpose_outbound_unavailable",
            "$.proxy.outbounds",
            &format!("cannot prepare the configured SOCKS5 outbounds: {error:#}"),
            "Make every selected password_file readable and verify each upstream address.",
        ));
    }
    if architecture_supported() && !artifact_available() {
        values.push(ExplicitDiagnostic::new(
            "interpose_native_artifact_unavailable",
            "$.execution.backend",
            "this binary does not contain a native interposition library",
            "Build Heimdall natively for this operating system and architecture.",
        ));
    }
    values
}

pub(crate) async fn run(
    config: &HeimdallConfig,
    policy_name: &str,
    command: &[String],
    evidence: &RunEvidence,
) -> Result<i32> {
    let diagnostics = diagnostics(config, policy_name);
    if let Some(diagnostic) = diagnostics.first() {
        bail!(
            "{} at {}: {}; fix: {}",
            diagnostic.code,
            diagnostic.path,
            diagnostic.message,
            diagnostic.hint
        );
    }
    if command.is_empty() {
        bail!("interpose requires a command");
    }
    preflight_command(&command[0])?;
    reject_existing_loader_state()?;

    let token = format!(
        "{}{}",
        uuid::Uuid::now_v7().simple(),
        uuid::Uuid::now_v7().simple()
    );
    let library = MaterializedLibrary::create(evidence.event_socket_path())?;
    let events = EventClient::connect(evidence.event_socket_path().to_path_buf())?;
    let proxy =
        ExplicitProxy::start_interpose(config, policy_name, events, token.as_bytes()).await?;

    evidence.log().emit(
        "run.warning",
        None,
        json!({
            "code": "interpose_partial_scope",
            "message": "only compatible dynamically linked connect and libc resolver calls are routed",
            "phase": "preflight",
            "context": {
                "backend": "interpose",
                "scope": "interposed_dynamic_calls",
                "failure_boundary": "interposed_calls_only",
                "client_can_bypass": true,
                "known_bypasses": [
                    "static_code",
                    "direct_syscalls",
                    "alternate_network_apis",
                    "loader_state_removal",
                    "unsupported_descendants",
                    "uninterposed_udp_calls",
                    "quic"
                ]
            }
        }),
    )?;
    if let Err(error) = evidence.ready("heimdall-run", None, &["transport"]) {
        proxy.shutdown().await?;
        return Err(error);
    }

    eprintln!(
        "heimdall run: backend=interpose scope=interposed_dynamic_calls failure_boundary=interposed_calls_only"
    );
    let mut child = child_command(
        command,
        library.path(),
        proxy.port(),
        &token,
        config
            .policy(policy_name)
            .expect("interpose diagnostics resolved the policy")
            .dns
            .mode,
    )?
    .spawn()
    .with_context(|| format!("execute {}", command[0]))?;
    let child_pid = child.id().context("wrapped command has no process ID")?;
    evidence.log().emit(
        "run.exec",
        Some(child_pid),
        json!({
            "child_pid": child_pid,
            "executable": command[0],
            "argv_count": command.len()
        }),
    )?;

    let status = child.wait().await.context("wait for interposed command");
    let shutdown = proxy.shutdown().await;
    let status = status?;
    shutdown?;
    Ok(status_exit_code(status))
}

fn child_command(
    command: &[String],
    library: &Path,
    port: u16,
    token: &str,
    dns: DnsMode,
) -> Result<Command> {
    let loader_variable = if cfg!(target_os = "macos") {
        "DYLD_INSERT_LIBRARIES"
    } else {
        "LD_PRELOAD"
    };
    let mut child = Command::new(&command[0]);
    child.args(&command[1..]).kill_on_drop(true);
    for variable in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
        "ftp_proxy",
        "FTP_PROXY",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_FORCE_FLAT_NAMESPACE",
        "HEIMDALL_INTERPOSE_ACTIVE",
        "HEIMDALL_INTERPOSE_PORT",
        "HEIMDALL_INTERPOSE_TOKEN",
        "HEIMDALL_INTERPOSE_DNS",
    ] {
        child.env_remove(variable);
    }
    child
        .env(loader_variable, library)
        .env("HEIMDALL_INTERPOSE_ACTIVE", "1")
        .env("HEIMDALL_INTERPOSE_PORT", port.to_string())
        .env("HEIMDALL_INTERPOSE_TOKEN", token)
        .env(
            "HEIMDALL_INTERPOSE_DNS",
            match dns {
                DnsMode::Fake => "fake",
                DnsMode::System => "system",
            },
        );
    if cfg!(target_os = "macos") {
        child.env("DYLD_FORCE_FLAT_NAMESPACE", "1");
    }
    Ok(child)
}

fn reject_existing_loader_state() -> Result<()> {
    let variables: &[&str] = if cfg!(target_os = "macos") {
        &["DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE"]
    } else {
        &["LD_PRELOAD"]
    };
    if let Some(variable) = variables.iter().find(|name| env::var_os(name).is_some()) {
        bail!(
            "interpose_loader_environment_conflict: {variable} is already set; fix: remove the existing loader injection before running Heimdall"
        );
    }
    Ok(())
}

struct MaterializedLibrary {
    path: PathBuf,
}

impl MaterializedLibrary {
    fn create(event_socket: &Path) -> Result<Self> {
        if !artifact_available() {
            bail!("native interpose library is unavailable in this binary");
        }
        let file_name = event_socket
            .file_name()
            .context("event socket has no file name")?
            .to_string_lossy();
        let path = event_socket.with_file_name(format!("{file_name}.{LIBRARY_NAME}"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .open(&path)
            .with_context(|| format!("create private interpose library {}", path.display()))?;
        if let Err(error) = file.write_all(LIBRARY_BYTES).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&path);
            return Err(error)
                .with_context(|| format!("materialize interpose library {}", path.display()));
        }
        #[cfg(target_os = "macos")]
        if let Err(error) = verify_macos_signature(&path) {
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for MaterializedLibrary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(target_os = "macos")]
fn verify_macos_signature(path: &Path) -> Result<()> {
    let status = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(path)
        .status()
        .context("verify embedded interpose library signature")?;
    anyhow::ensure!(
        status.success(),
        "embedded interpose library signature is invalid"
    );
    Ok(())
}

fn preflight_command(command: &str) -> Result<()> {
    let executable = resolve_executable(command)?;
    preflight_path(&executable, 0)
}

fn resolve_executable(command: &str) -> Result<PathBuf> {
    let path = Path::new(command);
    if path.components().count() > 1 {
        return fs::canonicalize(path).with_context(|| format!("resolve executable {command}"));
    }
    let search = env::var_os("PATH").context("PATH is unset")?;
    for directory in env::split_paths(&search) {
        let candidate = directory.join(command);
        if candidate.is_file() {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("resolve executable {}", candidate.display()));
        }
    }
    bail!("command not found on PATH: {command}")
}

fn preflight_path(path: &Path, depth: usize) -> Result<()> {
    if depth > 4 {
        bail!("interpose_target_unsupported: interpreter chain exceeds four entries");
    }
    let metadata = fs::metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    use std::os::unix::fs::MetadataExt;
    if metadata.mode() & 0o6000 != 0 {
        bail!(
            "interpose_target_unsupported: {} is setuid or setgid and may discard loader state",
            path.display()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("read executable {}", path.display()))?;
    if let Some(interpreter) = shebang_interpreter(&bytes)? {
        return preflight_path(&resolve_executable(&interpreter)?, depth + 1);
    }

    #[cfg(target_os = "linux")]
    return preflight_linux_elf(path, &bytes);
    #[cfg(target_os = "macos")]
    return preflight_macos_macho(path, &bytes);
}

fn shebang_interpreter(bytes: &[u8]) -> Result<Option<String>> {
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(bytes.len())
        .min(4096);
    let line = std::str::from_utf8(&bytes[2..end]).context("script shebang is not UTF-8")?;
    let mut words = line.split_ascii_whitespace();
    let interpreter = words.next().context("script shebang has no interpreter")?;
    if interpreter == "/usr/bin/env" {
        let name = words
            .find(|word| !word.starts_with('-'))
            .context("env shebang has no interpreter name")?;
        return Ok(Some(name.into()));
    }
    Ok(Some(interpreter.into()))
}

#[cfg(target_os = "linux")]
fn preflight_linux_elf(path: &Path, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(
        bytes.len() >= 64 && bytes.starts_with(b"\x7fELF"),
        "interpose_target_unsupported: {} is not an ELF executable or script",
        path.display()
    );
    anyhow::ensure!(
        bytes[4] == 2 && bytes[5] == 1,
        "interpose_target_unsupported: {} is not a little-endian ELF64 executable",
        path.display()
    );
    let program_offset = read_u64(bytes, 32)? as usize;
    let entry_size = usize::from(read_u16(bytes, 54)?);
    let entry_count = usize::from(read_u16(bytes, 56)?);
    anyhow::ensure!(entry_size >= 56, "ELF program header is truncated");
    let mut dynamic = false;
    for index in 0..entry_count {
        let offset = program_offset
            .checked_add(index.saturating_mul(entry_size))
            .context("ELF program header offset overflow")?;
        if read_u32(bytes, offset)? == 3 {
            dynamic = true;
            break;
        }
    }
    anyhow::ensure!(
        dynamic,
        "interpose_target_unsupported: {} is static and ignores LD_PRELOAD",
        path.display()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let value: [u8; 2] = bytes
        .get(offset..offset + 2)
        .context("ELF header is truncated")?
        .try_into()
        .expect("slice length checked");
    Ok(u16::from_le_bytes(value))
}

#[cfg(target_os = "linux")]
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let value: [u8; 4] = bytes
        .get(offset..offset + 4)
        .context("ELF header is truncated")?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(value))
}

#[cfg(target_os = "linux")]
fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let value: [u8; 8] = bytes
        .get(offset..offset + 8)
        .context("ELF header is truncated")?
        .try_into()
        .expect("slice length checked");
    Ok(u64::from_le_bytes(value))
}

#[cfg(target_os = "macos")]
fn preflight_macos_macho(path: &Path, bytes: &[u8]) -> Result<()> {
    let canonical = path.to_string_lossy();
    if canonical.starts_with("/System/")
        || canonical.starts_with("/usr/bin/")
        || canonical.starts_with("/bin/")
        || canonical.starts_with("/sbin/")
    {
        bail!(
            "interpose_target_unsupported: {} is SIP-protected and discards DYLD injection",
            path.display()
        );
    }
    anyhow::ensure!(
        matches!(
            bytes.get(..4),
            Some([0xcf, 0xfa, 0xed, 0xfe])
                | Some([0xca, 0xfe, 0xba, 0xbe])
                | Some([0xca, 0xfe, 0xba, 0xbf])
        ),
        "interpose_target_unsupported: {} is not a Mach-O executable or script",
        path.display()
    );
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["--display", "--verbose=4"])
        .arg(path)
        .output()
        .with_context(|| format!("inspect code signature for {}", path.display()))?;
    let detail = String::from_utf8_lossy(&output.stderr);
    anyhow::ensure!(
        !detail.lines().any(|line| {
            line.starts_with("CodeDirectory") && line.contains("flags=") && line.contains("runtime")
        }),
        "interpose_target_unsupported: {} enables Hardened Runtime and rejects DYLD injection",
        path.display()
    );
    Ok(())
}

fn status_exit_code(status: std::process::ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_artifact_matches_the_native_target() {
        assert!(artifact_available());
    }

    #[test]
    fn shebang_resolution_is_bounded_and_shell_safe() {
        assert_eq!(
            shebang_interpreter(b"#!/usr/bin/env python3\n").unwrap(),
            Some("python3".into())
        );
        assert_eq!(
            shebang_interpreter(b"#!/bin/sh -e\n").unwrap(),
            Some("/bin/sh".into())
        );
        assert_eq!(shebang_interpreter(b"ELF").unwrap(), None);
    }
}
