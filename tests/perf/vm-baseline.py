#!/usr/bin/env python3
"""Repeatable disposable-VM baseline for the real Heimdall data path."""

import argparse
import json
import math
import os
import platform
import shutil
import statistics
import subprocess
import tempfile
import time


def command(*argv):
    return [str(value) for value in argv]


def run_json(argv):
    return json.loads(subprocess.check_output(argv, text=True))


def run_ids(heimdall):
    return {
        run["run_id"]
        for run in run_json([heimdall, "logs", "list", "--json"])["runs"]
    }


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def aggregate(samples):
    grouped = {}
    for sample in samples:
        grouped.setdefault((sample["scenario"], sample["concurrency"]), []).append(sample)
    output = []
    for (scenario, concurrency), items in sorted(grouped.items()):
        wall = [item["wall_ns"] for item in items]
        output.append(
            {
                "scenario": scenario,
                "concurrency": concurrency,
                "samples": len(items),
                "operations": sum(item["operations"] for item in items),
                "wall_ns": {
                    "min": min(wall),
                    "median": int(statistics.median(wall)),
                    "p95": percentile(wall, 0.95),
                    "max": max(wall),
                },
                "operations_per_second": round(
                    sum(item["operations"] for item in items)
                    / (sum(wall) / 1_000_000_000),
                    3,
                ),
                "max_rss_kib": {
                    "max_process": max(item["max_rss_kib_max"] for item in items),
                    "max_batch_sum": max(item["max_rss_kib_sum"] for item in items),
                },
            }
        )
    return output


def timed_batch_gnu_time(time_bin, argv, concurrency, scenario, iteration):
    with tempfile.TemporaryDirectory(prefix="heimdall-benchmark-") as directory:
        processes = []
        start = time.monotonic_ns()
        for index in range(concurrency):
            rss_path = os.path.join(directory, f"rss-{index}")
            process = subprocess.Popen(
                [time_bin, "-f", "%M", "-o", rss_path, "--", *argv],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            processes.append((process, rss_path))
        failures = []
        rss = []
        for process, rss_path in processes:
            _, stderr = process.communicate()
            if process.returncode != 0:
                failures.append({"exit_code": process.returncode, "stderr": stderr[-400:]})
            with open(rss_path, encoding="ascii") as handle:
                rss.append(int(handle.read().strip()))
        wall_ns = time.monotonic_ns() - start
    if failures:
        raise RuntimeError(f"{scenario} failed: {failures}")
    return {
        "scenario": scenario,
        "iteration": iteration,
        "concurrency": concurrency,
        "operations": concurrency,
        "wall_ns": wall_ns,
        "max_rss_kib_max": max(rss),
        "max_rss_kib_sum": sum(rss),
    }


def heimdall_rss_kib():
    rss = []
    for entry in os.scandir("/proc"):
        if not entry.name.isdigit():
            continue
        try:
            with open(f"/proc/{entry.name}/status", encoding="ascii") as source:
                name = None
                process_rss = 0
                for line in source:
                    if line.startswith("Name:"):
                        name = line.split(maxsplit=1)[1].strip()
                    elif line.startswith("VmRSS:"):
                        process_rss = int(line.split()[1])
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if name == "heimdall":
            rss.append(process_rss)
    return rss


def timed_batch_procfs(argv, concurrency, scenario, iteration):
    processes = []
    start = time.monotonic_ns()
    for _ in range(concurrency):
        processes.append(
            subprocess.Popen(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        )

    max_process = 0
    max_batch_sum = 0
    while True:
        rss = heimdall_rss_kib()
        if rss:
            max_process = max(max_process, max(rss))
            max_batch_sum = max(max_batch_sum, sum(rss))
        if all(process.poll() is not None for process in processes):
            break
        time.sleep(0.002)

    failures = []
    for process in processes:
        _, stderr = process.communicate()
        if process.returncode != 0:
            failures.append({"exit_code": process.returncode, "stderr": stderr[-400:]})
    wall_ns = time.monotonic_ns() - start
    if failures:
        raise RuntimeError(f"{scenario} failed: {failures}")
    if max_process == 0:
        raise RuntimeError(f"{scenario} completed before procfs RSS was observable")
    return {
        "scenario": scenario,
        "iteration": iteration,
        "concurrency": concurrency,
        "operations": concurrency,
        "wall_ns": wall_ns,
        "max_rss_kib_max": max_process,
        "max_rss_kib_sum": max_batch_sum,
    }


def timed_batch(rss_source, time_bin, argv, concurrency, scenario, iteration):
    if rss_source == "gnu-time":
        return timed_batch_gnu_time(
            time_bin, argv, concurrency, scenario, iteration
        )
    return timed_batch_procfs(argv, concurrency, scenario, iteration)


def timed_transfer(argv, scenario, expected_bytes, capture, decrypt):
    start = time.monotonic_ns()
    completed = subprocess.run(argv, capture_output=True, text=True, check=False)
    wall_ns = time.monotonic_ns() - start
    if completed.returncode != 0:
        raise RuntimeError(
            f"{scenario} failed with {completed.returncode}: {completed.stderr[-400:]}"
        )
    try:
        transferred_bytes = int(float(completed.stdout.strip()))
    except ValueError as error:
        raise RuntimeError(
            f"{scenario} returned invalid byte count: {completed.stdout[-200:]!r}"
        ) from error
    if transferred_bytes != expected_bytes:
        raise RuntimeError(
            f"{scenario} transferred {transferred_bytes}, expected {expected_bytes} bytes"
        )
    return {
        "scenario": scenario,
        "transferred_bytes": transferred_bytes,
        "wall_ns": wall_ns,
        "bytes_per_second": round(
            transferred_bytes / (wall_ns / 1_000_000_000),
            3,
        ),
        "capture": capture,
        "decrypt": decrypt,
    }


def distribution_label():
    try:
        with open("/etc/os-release", encoding="utf-8") as source:
            values = {}
            for line in source:
                key, separator, value = line.rstrip().partition("=")
                if separator:
                    values[key] = value.strip('"')
        return values.get("PRETTY_NAME", values.get("NAME", "unknown"))
    except FileNotFoundError:
        return "unknown"


def memory_bytes():
    try:
        with open("/proc/meminfo", encoding="ascii") as source:
            for line in source:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024
    except FileNotFoundError:
        pass
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--scope", default="disposable-nixos-vm")
    parser.add_argument("--config", default="/etc/heimdall/config.toml")
    parser.add_argument("--relay-config", default="/etc/heimdall-test/relay.toml")
    parser.add_argument(
        "--no-capture-config",
        default="/etc/heimdall-test/benchmark-no-capture.toml",
    )
    parser.add_argument(
        "--capture-config", default="/etc/heimdall-test/benchmark-capture.toml"
    )
    parser.add_argument(
        "--relay-capture-config",
        default="/etc/heimdall-test/benchmark-relay-capture.toml",
    )
    parser.add_argument("--relay-ca-dir", default="/run/heimdall-test/relay")
    parser.add_argument("--fixture")
    parser.add_argument("--udp-client", default="/etc/heimdall-test/udp_client.py")
    parser.add_argument(
        "--udp-throughput", default="/etc/heimdall-test/udp-throughput.py"
    )
    parser.add_argument("--udp-response-prefix", default="udp-v4:")
    parser.add_argument("--proxy-policy", default="fake")
    parser.add_argument("--udp-policy", default="udp")
    parser.add_argument(
        "--rss-source", choices=("gnu-time", "procfs"), default="gnu-time"
    )
    args = parser.parse_args()
    if not 1 <= args.iterations <= 20:
        parser.error("--iterations must be between 1 and 20")

    heimdall = shutil.which("heimdall")
    time_bin = shutil.which("time") if args.rss_source == "gnu-time" else None
    if not heimdall:
        raise RuntimeError("heimdall must be on PATH")
    if args.rss_source == "gnu-time" and not time_bin:
        raise RuntimeError("GNU time must be on PATH for --rss-source=gnu-time")
    os.makedirs(args.relay_ca_dir, exist_ok=True)
    subprocess.check_call(
        [heimdall, "tls", "init-ca", "--dir", args.relay_ca_dir, "--json"],
        stdout=subprocess.DEVNULL,
    )
    before = run_ids(heimdall)
    relay_ca = os.path.join(args.relay_ca_dir, "ca.pem")

    if args.fixture:
        direct_tcp_client = command("python3", args.fixture, "http", "127.0.0.1")
        proxy_tcp_client = command("python3", args.fixture, "http", "fixture.test")
        proxy_udp_client = command("python3", args.fixture, "udp-host", "fixture.test")
        relay_tls_client = command("python3", args.fixture, "tls", relay_ca)
    else:
        direct_tcp_client = command("curl", "-fsS", "http://127.0.0.1:18080/")
        proxy_tcp_client = command("curl", "-fsS", "http://fixture.test:18080/")
        proxy_udp_client = command(
            "python3",
            args.udp_client,
            "fixture.test",
            "18082",
            f"{args.udp_response_prefix}probe",
        )
        relay_tls_client = command(
            "curl", "--cacert", relay_ca, "-fsS", "https://fixture.test:18444/"
        )

    scenarios = {
        "cold_start": command(
            heimdall,
            "--config",
            args.config,
            "run",
            "--policy",
            "direct",
            "--",
            "true",
        ),
        "direct_tcp": command(
            heimdall,
            "--config",
            args.config,
            "run",
            "--policy",
            "direct",
            "--",
            *direct_tcp_client,
        ),
        "proxy_tcp": command(
            heimdall,
            "--config",
            args.config,
            "run",
            "--policy",
            args.proxy_policy,
            "--",
            *proxy_tcp_client,
        ),
        "proxy_udp": command(
            heimdall,
            "--config",
            args.config,
            "run",
            "--policy",
            args.udp_policy,
            "--",
            *proxy_udp_client,
        ),
        "relay_tls": command(
            heimdall,
            "--config",
            args.relay_config,
            "run",
            "--policy",
            args.proxy_policy,
            "--",
            *relay_tls_client,
        ),
    }

    samples = []
    for name, argv in scenarios.items():
        timed_batch(args.rss_source, time_bin, argv, 1, name, 0)
        for iteration in range(1, args.iterations + 1):
            samples.append(
                timed_batch(
                    args.rss_source, time_bin, argv, 1, name, iteration
                )
            )
    for concurrency in (1, 10, 50):
        samples.append(
            timed_batch(
                args.rss_source,
                time_bin,
                scenarios["cold_start"],
                concurrency,
                "concurrent_cold_start",
                1,
            )
        )

    tcp_bytes = 16 * 1024 * 1024
    tcp_path = f"/bytes/{tcp_bytes}"
    curl_output = ["-fsS", "-o", "/dev/null", "-w", "%{size_download}"]
    udp_sent_bytes = 8 * 1024 * 1024
    udp_chunk_bytes = 8192
    udp_packets = math.ceil(udp_sent_bytes / udp_chunk_bytes)
    udp_transferred_bytes = (2 * udp_sent_bytes) + (
        len(args.udp_response_prefix.encode()) * udp_packets
    )
    if args.fixture:
        direct_tcp_transfer = command(
            "python3", args.fixture, "http-bytes", "127.0.0.1", tcp_bytes
        )
        proxy_tcp_transfer = command(
            "python3", args.fixture, "http-bytes", "fixture.test", tcp_bytes
        )
        relay_tls_transfer = command(
            "python3", args.fixture, "tls-bytes", relay_ca, tcp_bytes
        )
    else:
        direct_tcp_transfer = command(
            "curl", *curl_output, f"http://127.0.0.1:18080{tcp_path}"
        )
        proxy_tcp_transfer = command(
            "curl", *curl_output, f"http://fixture.test:18080{tcp_path}"
        )
        relay_tls_transfer = command(
            "curl",
            "--cacert",
            relay_ca,
            *curl_output,
            f"https://fixture.test:18444{tcp_path}",
        )
    throughput = [
        timed_transfer(
            command(
                heimdall,
                "--config",
                args.no_capture_config,
                "run",
                "--policy",
                "direct",
                "--",
                *direct_tcp_transfer,
            ),
            "direct_tcp_no_capture",
            tcp_bytes,
            "off",
            "off",
        ),
        timed_transfer(
            command(
                heimdall,
                "--config",
                args.no_capture_config,
                "run",
                "--policy",
                args.proxy_policy,
                "--",
                *proxy_tcp_transfer,
            ),
            "proxy_tcp_no_capture",
            tcp_bytes,
            "off",
            "off",
        ),
        timed_transfer(
            command(
                heimdall,
                "--config",
                args.no_capture_config,
                "run",
                "--policy",
                args.udp_policy,
                "--",
                "python3",
                args.udp_throughput,
                "fixture.test",
                "18082",
                "--bytes",
                udp_sent_bytes,
                "--chunk-bytes",
                udp_chunk_bytes,
                "--response-prefix",
                args.udp_response_prefix,
            ),
            "proxy_udp_no_capture",
            udp_transferred_bytes,
            "off",
            "off",
        ),
        timed_transfer(
            command(
                heimdall,
                "--config",
                args.capture_config,
                "run",
                "--policy",
                args.proxy_policy,
                "--",
                *proxy_tcp_transfer,
            ),
            "proxy_tcp_capture",
            tcp_bytes,
            "transport",
            "off",
        ),
        timed_transfer(
            command(
                heimdall,
                "--config",
                args.relay_capture_config,
                "run",
                "--policy",
                args.proxy_policy,
                "--",
                *relay_tls_transfer,
            ),
            "relay_tls_capture",
            tcp_bytes,
            "tls_plaintext.relay",
            "relay",
        ),
    ]

    after = run_ids(heimdall)
    summaries = [
        run_json([heimdall, "logs", "summary", "--run", run_id, "--json"])
        for run_id in sorted(after - before)
    ]
    missing = sum(item["sequence"]["missing_records"] for item in summaries)
    out_of_order = sum(item["sequence"]["out_of_order_records"] for item in summaries)
    incomplete = sum(not item["complete"] for item in summaries)
    active_flows = sum(item["flows"]["active"] for item in summaries)
    failed_flows = sum(
        sum(item["flows"]["failures_by_code"].values()) for item in summaries
    )
    error_events = sum(item["error_events"]["total"] for item in summaries)
    report = {
        "contract": "heimdall.benchmark/v1",
        "scope": args.scope,
        "environment": {
            "distribution": distribution_label(),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "cpu_count": os.cpu_count(),
            "memory_bytes": memory_bytes(),
            "heimdall": subprocess.check_output([heimdall, "--version"], text=True).strip(),
            "iterations": args.iterations,
            "rss_source": (
                "gnu-time-rusage"
                if args.rss_source == "gnu-time"
                else "procfs-heimdall-processes"
            ),
        },
        "samples": samples,
        "aggregates": aggregate(samples),
        "throughput": throughput,
        "event_integrity": {
            "runs": len(summaries),
            "incomplete_runs": incomplete,
            "missing_records": missing,
            "out_of_order_records": out_of_order,
            "active_flows_after_close": active_flows,
            "failed_flows": failed_flows,
            "error_events": error_events,
        },
        "interpretation": "Environment-specific baseline, not a universal performance claim.",
    }
    if (
        not summaries
        or incomplete
        or missing
        or out_of_order
        or active_flows
        or failed_flows
        or error_events
    ):
        raise RuntimeError(f"event integrity failed: {report['event_integrity']}")
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))


if __name__ == "__main__":
    main()
