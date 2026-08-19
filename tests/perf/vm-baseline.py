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


def timed_batch(time_bin, argv, concurrency, scenario, iteration):
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 20:
        parser.error("--iterations must be between 1 and 20")

    heimdall = shutil.which("heimdall")
    time_bin = shutil.which("time")
    if not heimdall or not time_bin:
        raise RuntimeError("heimdall and GNU time must be on PATH")
    config = "/etc/heimdall/config.toml"
    relay_config = "/etc/heimdall-test/relay.toml"
    no_capture_config = "/etc/heimdall-test/benchmark-no-capture.toml"
    capture_config = "/etc/heimdall-test/benchmark-capture.toml"
    relay_capture_config = "/etc/heimdall-test/benchmark-relay-capture.toml"
    subprocess.check_call(
        [heimdall, "tls", "init-ca", "--dir", "/run/heimdall-test/relay", "--json"],
        stdout=subprocess.DEVNULL,
    )
    before = run_ids(heimdall)

    scenarios = {
        "cold_start": command(heimdall, "--config", config, "run", "--policy", "direct", "--", "true"),
        "direct_tcp": command(heimdall, "--config", config, "run", "--policy", "direct", "--", "curl", "-fsS", "http://127.0.0.1:18080/"),
        "proxy_tcp": command(heimdall, "--config", config, "run", "--policy", "fake", "--", "curl", "-fsS", "http://fixture.test:18080/"),
        "proxy_udp": command(heimdall, "--config", config, "run", "--policy", "udp", "--", "python3", "/etc/heimdall-test/udp_client.py", "fixture.test", "18082", "udp-v4:probe"),
        "relay_tls": command(heimdall, "--config", relay_config, "run", "--policy", "fake", "--", "curl", "--cacert", "/run/heimdall-test/relay/ca.pem", "-fsS", "https://fixture.test:18444/"),
    }

    samples = []
    for name, argv in scenarios.items():
        timed_batch(time_bin, argv, 1, name, 0)
        for iteration in range(1, args.iterations + 1):
            samples.append(timed_batch(time_bin, argv, 1, name, iteration))
    for concurrency in (1, 10, 50):
        samples.append(
            timed_batch(
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
    udp_transferred_bytes = (2 * udp_sent_bytes) + (len("udp-v4:") * udp_packets)
    throughput = [
        timed_transfer(
            command(
                heimdall,
                "--config",
                no_capture_config,
                "run",
                "--policy",
                "direct",
                "--",
                "curl",
                *curl_output,
                f"http://127.0.0.1:18080{tcp_path}",
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
                no_capture_config,
                "run",
                "--policy",
                "fake",
                "--",
                "curl",
                *curl_output,
                f"http://fixture.test:18080{tcp_path}",
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
                no_capture_config,
                "run",
                "--policy",
                "udp",
                "--",
                "python3",
                "/etc/heimdall-test/udp-throughput.py",
                "fixture.test",
                "18082",
                "--bytes",
                udp_sent_bytes,
                "--chunk-bytes",
                udp_chunk_bytes,
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
                capture_config,
                "run",
                "--policy",
                "fake",
                "--",
                "curl",
                *curl_output,
                f"http://fixture.test:18080{tcp_path}",
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
                relay_capture_config,
                "run",
                "--policy",
                "fake",
                "--",
                "curl",
                "--cacert",
                "/run/heimdall-test/relay/ca.pem",
                *curl_output,
                f"https://fixture.test:18444{tcp_path}",
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
        "scope": "disposable-nixos-vm",
        "environment": {
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "cpu_count": os.cpu_count(),
            "heimdall": subprocess.check_output([heimdall, "--version"], text=True).strip(),
            "iterations": args.iterations,
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
