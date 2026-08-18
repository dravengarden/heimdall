//! Agent-first access to per-run event logs.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

use crate::event_log::{
    EVENT_CONTRACT, EVENT_SCHEMA, Event, RUN_SCHEMA, RunManifest, read_manifest, request_rotation,
    runs_root,
};

#[derive(Subcommand, Debug)]
pub enum LogsCmd {
    /// Print a bundled JSON Schema without network access.
    Schema(SchemaArgs),
    /// List discovered runs as one JSON document.
    List(JsonArgs),
    /// Resolve one run ID to its absolute directory.
    Path(RunJsonArgs),
    /// Stream matching event objects as JSONL.
    Query(QueryArgs),
    /// Read a run and optionally follow it across segment rotation.
    Tail(TailArgs),
    /// Ask an active run to close its current segment and open the next.
    Rotate(RunJsonArgs),
    /// Verify event sequence, segment digests, and manifest consistency.
    Verify(RunJsonArgs),
    /// Preview or remove closed run directories according to retention limits.
    Prune(PruneArgs),
}

#[derive(Args, Debug)]
pub struct SchemaArgs {
    /// Print the heimdall.event schema version (currently v1).
    #[arg(
        long,
        value_name = "VERSION",
        conflicts_with = "run",
        required_unless_present = "run"
    )]
    event: Option<String>,
    /// Print the heimdall.run schema version (currently v1).
    #[arg(
        long,
        value_name = "VERSION",
        conflicts_with = "event",
        required_unless_present = "event"
    )]
    run: Option<String>,
}

#[derive(Args, Debug)]
pub struct JsonArgs {
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug)]
pub struct RunJsonArgs {
    /// UUIDv7 run identifier.
    #[arg(long)]
    run: Uuid,
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Args, Debug, Clone)]
pub struct QueryArgs {
    /// UUIDv7 run identifier.
    #[arg(long)]
    run: Uuid,
    /// Match an event kind. Repeat to select multiple kinds.
    #[arg(long)]
    kind: Vec<String>,
    /// Match one flow UUIDv7.
    #[arg(long)]
    flow: Option<Uuid>,
    /// Include records at or after this sequence.
    #[arg(long)]
    since_seq: Option<u64>,
    /// Include records at or before this sequence.
    #[arg(long)]
    until_seq: Option<u64>,
    /// Stream raw heimdall.event/v1 objects, one per line.
    #[arg(long)]
    jsonl: bool,
}

#[derive(Args, Debug)]
pub struct TailArgs {
    #[command(flatten)]
    query: QueryArgs,
    /// Continue reading new records and numbered segments until the run closes.
    #[arg(long)]
    follow: bool,
}

#[derive(Args, Debug)]
pub struct PruneArgs {
    /// Select closed runs older than this duration, for example 30d or 12h.
    #[arg(long)]
    older_than: Option<String>,
    /// Always retain this many newest runs.
    #[arg(long, default_value_t = 20)]
    keep_last: usize,
    /// Actually delete selected run directories. Without this flag, only preview.
    #[arg(long)]
    apply: bool,
    /// Emit one machine-readable JSON document.
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct RunSummary {
    run_id: Uuid,
    state: String,
    started_at: String,
    closed_at: Option<String>,
    policy: String,
    backend: String,
    run_dir: String,
}

pub fn run(command: LogsCmd) -> Result<()> {
    match command {
        LogsCmd::Schema(args) => schema(args),
        LogsCmd::List(args) => list(args),
        LogsCmd::Path(args) => path(args),
        LogsCmd::Query(args) => query(&args, 0).map(|_| ()),
        LogsCmd::Tail(args) => tail(args),
        LogsCmd::Rotate(args) => rotate(args),
        LogsCmd::Verify(args) => verify(args),
        LogsCmd::Prune(args) => prune(args),
    }
}

fn schema(args: SchemaArgs) -> Result<()> {
    let raw = match (args.event.as_deref(), args.run.as_deref()) {
        (Some("v1"), None) => EVENT_SCHEMA,
        (None, Some("v1")) => RUN_SCHEMA,
        (Some(version), None) => anyhow::bail!("unsupported event schema `{version}`"),
        (None, Some(version)) => anyhow::bail!("unsupported run schema `{version}`"),
        _ => anyhow::bail!("select exactly one of --event v1 or --run v1"),
    };
    let value: Value = serde_json::from_str(raw).context("decode bundled JSON Schema")?;
    println!("{}", serde_json::to_string(&value)?);
    Ok(())
}

fn list(args: JsonArgs) -> Result<()> {
    let runs = discover_runs()?;
    let summaries = runs
        .into_iter()
        .map(|(run_dir, manifest)| RunSummary {
            run_id: manifest.run_id,
            state: manifest.state,
            started_at: manifest.started_at,
            closed_at: manifest.closed_at,
            policy: manifest.policy,
            backend: manifest.backend,
            run_dir: absolute(&run_dir).display().to_string(),
        })
        .collect::<Vec<_>>();
    let value = json!({
        "contract": "heimdall.logs.list/v1",
        "runs_root": absolute(&runs_root()?).display().to_string(),
        "runs": summaries
    });
    print_document(&value, args.json)
}

fn path(args: RunJsonArgs) -> Result<()> {
    let (run_dir, manifest) = find_run(args.run)?;
    let value = json!({
        "contract": "heimdall.logs.path/v1",
        "run_id": manifest.run_id,
        "state": manifest.state,
        "run_dir": absolute(&run_dir).display().to_string(),
        "manifest": absolute(&run_dir.join("run.json")).display().to_string()
    });
    print_document(&value, args.json)
}

fn rotate(args: RunJsonArgs) -> Result<()> {
    let response = match request_rotation(args.run) {
        Ok(response) => response,
        Err(error) => json!({
            "contract": "heimdall.logs.control/v1",
            "ok": false,
            "code": "run_not_active",
            "message": error.to_string()
        }),
    };
    let ok = response["ok"].as_bool() == Some(true);
    print_document(&response, args.json)?;
    anyhow::ensure!(ok, "log rotation request failed");
    Ok(())
}

fn tail(args: TailArgs) -> Result<()> {
    let mut last_seq = 0;
    loop {
        last_seq = query(&args.query, last_seq)?;
        if !args.follow {
            return Ok(());
        }
        let (_, manifest) = find_run(args.query.run)?;
        if matches!(manifest.state.as_str(), "closed" | "failed") {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn query(args: &QueryArgs, after_seq: u64) -> Result<u64> {
    anyhow::ensure!(args.jsonl, "only --jsonl output is supported");
    let (run_dir, _) = find_run(args.run)?;
    let mut last_seq = after_seq;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for segment in segment_paths(&run_dir)? {
        let file = File::open(&segment).with_context(|| format!("open {}", segment.display()))?;
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = line
                .with_context(|| format!("read {} line {}", segment.display(), line_number + 1))?;
            let event: Event = serde_json::from_str(&line).with_context(|| {
                format!("decode {} line {}", segment.display(), line_number + 1)
            })?;
            if event.seq <= after_seq {
                continue;
            }
            last_seq = last_seq.max(event.seq);
            if !matches_query(&event, args) {
                continue;
            }
            output
                .write_all(line.as_bytes())
                .context("write queried event")?;
            output.write_all(b"\n").context("write event newline")?;
        }
    }
    output.flush().context("flush queried events")?;
    Ok(last_seq)
}

fn matches_query(event: &Event, args: &QueryArgs) -> bool {
    (args.kind.is_empty() || args.kind.iter().any(|kind| kind == &event.kind))
        && args.flow.is_none_or(|flow| event.flow_id == Some(flow))
        && args.since_seq.is_none_or(|seq| event.seq >= seq)
        && args.until_seq.is_none_or(|seq| event.seq <= seq)
}

fn verify(args: RunJsonArgs) -> Result<()> {
    let (run_dir, manifest) = find_run(args.run)?;
    let value = verify_run(&run_dir, &manifest)?;
    let valid = value["valid"] == true;
    print_document(&value, args.json)?;
    anyhow::ensure!(valid, "event log verification failed");
    Ok(())
}

fn verify_run(run_dir: &Path, manifest: &RunManifest) -> Result<Value> {
    let mut errors = Vec::new();
    let mut expected_seq = 1u64;
    let mut event_count = 0u64;
    let segment_paths = segment_paths(run_dir)?;
    let mut observed_ranges = BTreeMap::new();
    for segment in &segment_paths {
        let segment_name = segment
            .file_name()
            .and_then(|value| value.to_str())
            .context("event segment filename is not UTF-8")?
            .to_owned();
        let mut first_seq = None;
        let mut last_seq = None;
        let file = match File::open(segment) {
            Ok(file) => file,
            Err(error) => {
                errors.push(format!("open {}: {error}", segment.display()));
                continue;
            }
        };
        for (line_number, line) in BufReader::new(file).lines().enumerate() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    errors.push(format!(
                        "read {} line {}: {error}",
                        segment.display(),
                        line_number + 1
                    ));
                    break;
                }
            };
            let event: Event = match serde_json::from_str(&line) {
                Ok(event) => event,
                Err(error) => {
                    errors.push(format!(
                        "decode {} line {}: {error}",
                        segment.display(),
                        line_number + 1
                    ));
                    break;
                }
            };
            if event.schema != EVENT_CONTRACT {
                errors.push(format!("sequence {} has unsupported schema", event.seq));
            }
            if event.run_id != manifest.run_id {
                errors.push(format!("sequence {} has mismatched run_id", event.seq));
            }
            if event.seq != expected_seq {
                errors.push(format!(
                    "expected sequence {expected_seq}, found {}",
                    event.seq
                ));
                expected_seq = event.seq;
            }
            first_seq.get_or_insert(event.seq);
            last_seq = Some(event.seq);
            expected_seq += 1;
            event_count += 1;
        }
        observed_ranges.insert(segment_name, (first_seq, last_seq));
    }
    for segment in &manifest.segments {
        let path = safe_segment_path(run_dir, &segment.file)?;
        match observed_ranges.get(&segment.file) {
            Some((Some(first_seq), Some(last_seq))) => {
                if *first_seq != segment.first_seq || *last_seq != segment.last_seq {
                    errors.push(format!(
                        "{} sequence range mismatch: expected {}-{}, found {first_seq}-{last_seq}",
                        segment.file, segment.first_seq, segment.last_seq
                    ));
                }
            }
            Some((None, None)) => errors.push(format!("{} is empty", segment.file)),
            Some(_) => errors.push(format!("{} has an incomplete sequence range", segment.file)),
            None => errors.push(format!("{} is missing", segment.file)),
        }
        match fs::metadata(&path) {
            Ok(metadata) if metadata.len() == segment.bytes => {}
            Ok(metadata) => errors.push(format!(
                "{} byte count mismatch: expected {}, found {}",
                segment.file,
                segment.bytes,
                metadata.len()
            )),
            Err(error) => errors.push(format!("inspect {}: {error}", segment.file)),
        }
        match sha256_file(&path) {
            Ok(digest) if digest == segment.sha256 => {}
            Ok(digest) => errors.push(format!(
                "{} digest mismatch: expected {}, found {digest}",
                segment.file, segment.sha256
            )),
            Err(error) => errors.push(format!("verify {}: {error}", segment.file)),
        }
    }
    if matches!(manifest.state.as_str(), "closed" | "failed")
        && segment_paths.len() != manifest.segments.len()
    {
        errors.push(format!(
            "final manifest lists {} segments but {} files exist",
            manifest.segments.len(),
            segment_paths.len()
        ));
    }
    if manifest.state == "closed"
        && manifest
            .segments
            .last()
            .is_none_or(|segment| segment.last_seq + 1 != expected_seq)
    {
        errors.push("closed manifest does not finalize the last event".into());
    }
    Ok(json!({
        "contract": "heimdall.logs.verify/v1",
        "run_id": manifest.run_id,
        "valid": errors.is_empty(),
        "state": manifest.state,
        "events": event_count,
        "segments": manifest.segments.len(),
        "errors": errors
    }))
}

fn prune(args: PruneArgs) -> Result<()> {
    let cutoff = args
        .older_than
        .as_deref()
        .map(parse_age)
        .transpose()?
        .map(|age| OffsetDateTime::now_utc() - age);
    let mut runs = discover_runs()?;
    runs.sort_by(|left, right| right.1.started_at.cmp(&left.1.started_at));
    let mut candidates = Vec::new();
    for (index, (run_dir, manifest)) in runs.iter().enumerate() {
        if index < args.keep_last || !matches!(manifest.state.as_str(), "closed" | "failed") {
            continue;
        }
        if let Some(cutoff) = cutoff {
            let closed = manifest
                .closed_at
                .as_deref()
                .context("closed run is missing closed_at")?;
            let closed = OffsetDateTime::parse(closed, &Rfc3339)
                .with_context(|| format!("parse closed_at for {}", manifest.run_id))?;
            if closed >= cutoff {
                continue;
            }
        }
        candidates.push((run_dir.clone(), manifest.run_id, directory_bytes(run_dir)?));
    }
    if args.apply {
        for (run_dir, _, _) in &candidates {
            fs::remove_dir_all(run_dir)
                .with_context(|| format!("remove run directory {}", run_dir.display()))?;
        }
    }
    let value = json!({
        "contract": "heimdall.logs.prune/v1",
        "applied": args.apply,
        "candidates": candidates.iter().map(|(path, run_id, bytes)| json!({
            "run_id": run_id,
            "run_dir": absolute(path).display().to_string(),
            "bytes": bytes,
            "reason": "retention"
        })).collect::<Vec<_>>()
    });
    print_document(&value, args.json)
}

fn discover_runs() -> Result<Vec<(PathBuf, RunManifest)>> {
    let root = runs_root()?;
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut manifests = Vec::new();
    collect_manifests(&root, &mut manifests)?;
    let mut runs = manifests
        .into_iter()
        .map(|path| {
            let manifest = read_manifest(&path)?;
            let run_dir = path
                .parent()
                .context("run manifest has no parent")?
                .to_path_buf();
            Ok((run_dir, manifest))
        })
        .collect::<Result<Vec<_>>>()?;
    runs.sort_by(|left, right| right.1.started_at.cmp(&left.1.started_at));
    Ok(runs)
}

fn collect_manifests(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(directory).with_context(|| format!("read {}", directory.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", directory.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_manifests(&entry.path(), output)?;
        } else if file_type.is_file() && entry.file_name() == "run.json" {
            output.push(entry.path());
        }
    }
    Ok(())
}

fn find_run(run_id: Uuid) -> Result<(PathBuf, RunManifest)> {
    discover_runs()?
        .into_iter()
        .find(|(_, manifest)| manifest.run_id == run_id)
        .with_context(|| format!("run_not_found: {run_id}"))
}

fn segment_paths(run_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(run_dir).with_context(|| format!("read {}", run_dir.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", run_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        let matches = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with("events-") && name.ends_with(".jsonl"));
        if file_type.is_file() && matches {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn safe_segment_path(run_dir: &Path, file: &str) -> Result<PathBuf> {
    anyhow::ensure!(
        file.starts_with("events-")
            && file.ends_with(".jsonl")
            && !file.contains('/')
            && !file.contains(".."),
        "unsafe segment path `{file}`"
    );
    Ok(run_dir.join(file))
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let count = std::io::Read::read(&mut file, &mut buffer)
            .with_context(|| format!("hash {}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

fn directory_bytes(path: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in fs::read_dir(path).with_context(|| format!("read {}", path.display()))? {
        let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_symlink() {
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("inspect {}", entry.path().display()))?;
        if file_type.is_dir() {
            total = total.saturating_add(directory_bytes(&entry.path())?);
        } else if file_type.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn parse_age(value: &str) -> Result<time::Duration> {
    let (digits, unit) = value.split_at(value.len().saturating_sub(1));
    let amount = digits
        .parse::<i64>()
        .with_context(|| format!("invalid retention duration `{value}`"))?;
    anyhow::ensure!(amount > 0, "retention duration must be positive");
    match unit {
        "d" => Ok(time::Duration::days(amount)),
        "h" => Ok(time::Duration::hours(amount)),
        "m" => Ok(time::Duration::minutes(amount)),
        _ => anyhow::bail!("retention duration must end in d, h, or m"),
    }
}

fn absolute(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn print_document(value: &impl Serialize, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_log::RunLog;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "heimdall-logs-{name}-{}-{}",
            std::process::id(),
            Uuid::now_v7()
        ))
    }

    #[test]
    fn parses_retention_durations() {
        assert_eq!(parse_age("30d").unwrap(), time::Duration::days(30));
        assert_eq!(parse_age("12h").unwrap(), time::Duration::hours(12));
        assert!(parse_age("0d").is_err());
        assert!(parse_age("30").is_err());
    }

    #[test]
    fn segment_paths_reject_traversal() {
        assert!(safe_segment_path(Path::new("/tmp/run"), "../events-1.jsonl").is_err());
        assert!(safe_segment_path(Path::new("/tmp/run"), "events-000001.jsonl").is_ok());
    }

    #[test]
    fn verification_detects_segment_tampering() {
        let root = test_root("verify");
        let log = RunLog::create_at(&root, &["true".into()], "default", "daemon").unwrap();
        log.ready("heimdall-daemon", Some("127.0.0.1:7312"), &["transport"])
            .unwrap();
        log.emit(
            "run.exec",
            Some(42),
            json!({"child_pid": 42, "executable": "true", "argv_count": 1}),
        )
        .unwrap();
        log.finish(0, true).unwrap();
        let run_dir = log.run_dir().unwrap();
        let manifest = read_manifest(&run_dir.join("run.json")).unwrap();

        let valid = verify_run(&run_dir, &manifest).unwrap();
        assert_eq!(valid["valid"], true);
        assert_eq!(valid["events"], 4);

        let segment = safe_segment_path(&run_dir, &manifest.segments[0].file).unwrap();
        let mut file = fs::OpenOptions::new().append(true).open(segment).unwrap();
        file.write_all(b" ").unwrap();
        file.sync_all().unwrap();

        let invalid = verify_run(&run_dir, &manifest).unwrap();
        assert_eq!(invalid["valid"], false);
        assert!(invalid["errors"].as_array().unwrap().iter().any(|error| {
            error
                .as_str()
                .is_some_and(|message| message.contains("digest mismatch"))
        }));
        fs::remove_dir_all(root).unwrap();
    }
}
