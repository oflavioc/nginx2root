# nginx2root lab reproductions

Censys Research's isolated-lab reproductions of the five nginx2root vulnerabilities. This repository contains a compact HTTP/2 accounting proof of concept, packet captures, and a guarded compatibility runner.

**Start here:** the [single-file compact PoC](h2c_flow_control_test.py) demonstrates the `CVE-2026-123007` accounting error on every release from nginx 1.30.0 through 1.31.8, with the patched 1.31.9 control over cleartext h2c. It is not an RCE exploit.

## Quick start

Requirements: Docker with the `nginx:1.31.8` and `nginx:1.31.9` images, and Python 3.10 or newer. Use a disposable lab you own.

```sh
uv run python -I h2c_flow_control_test.py \
  --docker \
  --output /tmp/nginx2root-compact-evidence.json \
  --command-timeout 45 \
  --client-timeout 45 \
  --acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB
```

Expected result:

```text
PASS: vulnerable h2c accepted over-credit; patched control rejected it
```

The script creates an internal Docker network, runs vulnerable and patched targets, and cleans up afterward. It uses no published ports or host networking. The JSON evidence records the script hash, target results, and cleanup status. Timeouts are capped at 120 seconds.

Read [compact PoC instructions](docs/COMPACT-POC.md) and the [safety boundary](SECURITY.md).

## What the compact PoC does

The client consumes the initial connection window, queues an 8 MB response, resets the stream, and probes the accounting error with a one-byte update. Vulnerable nginx accepts it and answers PING. Patched nginx rejects the earlier 4 MiB update and closes the connection. The differential is verified on every release from 1.30.0 through 1.31.8, with 1.31.9 as the patched control.

It does **not** corrupt memory, reclaim objects, install callbacks, execute commands, or create a shell. TLS support for the compact test is not validated.

The retained evidence includes a **5.69 MB vulnerable capture** and a **1.41 MB patched capture**. They contain private lab addresses and stock nginx content, with no personal information or credentials.

## Compatibility matrix

### Compact accounting PoC

| Version | Native x86-64 | Native arm64 | Configuration | Result |
| --- | --- | --- | --- | --- |
| 1.30.0–1.30.6 | Verified | Verified on 1.30.0 and 1.30.6 | h2c, one worker | Accounting error confirmed |
| 1.31.0–1.31.5 | Verified | Verified on 1.31.0 and 1.31.5 | h2c, one worker | Accounting error confirmed |
| 1.31.6 | Verified | Verified | h2c, one worker | Accounting error confirmed |
| 1.31.7 | Verified | Verified | h2c, one worker | Accounting error confirmed; full RCE unverified |
| 1.31.8 | Verified | Verified | h2c, one worker | Accounting error confirmed; full RCE reproduced once (2026-11-21) |
| 1.31.9 | Rejects probe | Rejects probe | Patched control | No accounting proof |

Additional native x86-64 coverage: one, two, and four workers; fresh, 40-request, and 200-request heap states; static full and Range responses; buffered upstream full, Range, chunked, and close-delimited responses. Unbuffered proxying is inconclusive because it leaves insufficient queued data.

See [worker/heap evidence](evidence/release-validation/worker-heap-matrix.md), [arm64 evidence](evidence/release-validation/arm64-results-summary.json), and [response-delivery evidence](evidence/release-validation/response-matrix.csv).

### Full RCE

| CVE | Tested path | Current result |
| --- | --- | --- |
| `CVE-2026-123007` | HTTP/2 flow control | Rapid7's full RCE chain reproduced once, on 2026-11-21, against an owned nginx 1.31.8 target (native x86-64 AVX-512). Not run on 1.31.6. |
| `CVE-2026-123633` | HTTP/2 with upstream proxying | UAF and stock worker crash reproduced; no unified RCE adapter. |
| `CVE-2026-123634` | Runtime DNS resolution with subrequests | ASAN UAF and custom-debug crashes; no stock-image crash or unified RCE adapter. |
| `CVE-2026-121810` | HTTP/3 with upstream proxying | Not reproduced. |
| `CVE-2026-113425` | Mail proxy with `auth_http` | Command execution confirmed from retained artifacts on nginx 1.31.8 (three runs) and 1.31.7 (one run), with patched 1.31.9 negative control. Not independently replayed. |

A worker crash, sanitizer report, allocation reuse, or client dispatch message is not command execution. RCE requires an independently created marker and a patched negative control.

## Full RCE evidence

On 2026-11-21, Censys reproduced Rapid7's complete `CVE-2026-123007` exploit chain exactly once, against a disposable, isolated nginx 1.31.8 container we own, driven from a `python:3.10` container with the native streamer recompiled from source, on an AVX-512 host (Ryzen 9 7950X). The profile `golden-nginx-1.31.8-debian13-amd64` was auto-selected. This single run dispatched ~119.02 GiB of plaintext over 16 auxiliary connections in ~190 seconds, captured a 14,393-byte memory disclosure, and resolved ASLR (H=0x594f9ac415c0, nginx=0x594f819ad840, libc=0x72978269a000), recovering the in-band libc `system` at 0x7297826ed090. It then reclaimed the overwritten pool and dispatched a cleanup callback invoking `system(command)`.

The harmless command, passed via `--cmd`, was:

```sh
touch /tmp/pwn-realrun-01
```

An independent check found the marker `/tmp/pwn-realrun-01` owned by UID/GID 101:101 with mode 644, proving command execution as the nginx worker. The worker then crashed with `free(): double free detected in tcache 2`, and worker process 22 exited on signal 6 at 2026/11/21 15:29:37. This single-shot, worker-crashing primitive was not host root, a kernel exploit, container escape, or a stable shell.

This was the only run. The chain was not run against the patched 1.31.9 build: the profile gate would reject a non-matching build, but no patched-control exploit run was performed.

See:

- [RCE evidence](evidence/cve-2026-123007/RCE-CONFIRMED.md) and [the marker record](evidence/cve-2026-123007/rapid7-rce-marker.txt), both documenting this single genuine run of 2026-11-21
- [Attack-chain diagram](docs/CVE-2026-123007-ATTACK-CHAIN.md)
- [Reproduction instructions](docs/REPRODUCTION.md)

The full exploit is **Rapid7's public work**, not a novel Censys exploit. Its source is not vendored here because the pinned upstream revision has no license file. See [third-party provenance](third_party/README.md).

## Compatibility testing

The [compatibility runner](docs/CVE-2026-123007-COMPATIBILITY.md) tests supplied exploit profiles against fresh and exercised heaps, with independent patched controls. It defaults to listing or dry-run and requires explicit local-lab acknowledgement for live execution.

The runner supports the supplied 1.31.6 and 1.31.8 profiles. A 1.31.7 profile requires separate calibration and validation; it is not supplied. The 1.31.9 image is a negative control, not a vulnerable result.

## Evidence and test commands

Read archived evidence without rerunning the full exploit:

```sh
uv sync
uv run python -m suite list --json
uv run python -m suite verify cve-2026-123007 --json
```

The archived result remains `archived`, not a fresh RCE verification.

Run the offline tests:

```sh
uv run pytest
```

CI also runs Python compilation, formatting checks, unit tests, and the real compact Docker differential.

## License

Censys-authored code, documents, and evidence are licensed under [Apache-2.0](LICENSE). This license does not cover linked upstream code, nginx, Docker images, or other third-party software. Those components retain their respective terms.

## Related research

- [Censys nginx2root research](https://nginx2root.censys.com/)
- [Censys nginx2root advisory](https://censys.com/advisory/nginx2root/)
- [Xint disclosure](https://xint.io/blog/nginx2root-remote-code-execution)
- [nginx security advisories](https://nginx.org/en/security_advisories.html)
