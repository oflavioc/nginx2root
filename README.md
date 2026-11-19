# nginx2root lab reproductions

Censys Research's isolated-lab reproductions of the five nginx2root vulnerabilities. This repository contains a compact HTTP/2 accounting proof of concept, packet captures, independent command-execution evidence, and a guarded compatibility runner.

**Start here:** the [single-file compact PoC](h2c_flow_control_test.py) demonstrates the `CVE-2026-123007` accounting error on nginx 1.31.6, 1.31.7, and 1.31.8, with the patched 1.31.9 control over cleartext h2c. It is not an RCE exploit.

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

The client consumes the initial connection window, queues an 8 MB response, resets the stream, and probes the accounting error with a one-byte update. Vulnerable nginx accepts it and answers PING. Patched nginx rejects the earlier 4 MiB update and closes the connection. The differential is verified on 1.31.6, 1.31.7, and 1.31.8, with 1.31.9 as the patched control.

It does **not** corrupt memory, reclaim objects, install callbacks, execute commands, or create a shell. TLS support for the compact test is not validated.

The retained evidence includes a **5.69 MB vulnerable capture** and a **1.41 MB patched capture**. They contain private lab addresses and stock nginx content, with no personal information or credentials.

## Results

| CVE | Tested path | Current result |
| --- | --- | --- |
| `CVE-2026-123007` | HTTP/2 flow control | Compact accounting differential. Rapid7's full RCE chain independently reproduced on matched native AVX512 profiles. |
| `CVE-2026-123633` | HTTP/2 with upstream proxying | UAF and stock worker crash reproduced; no unified RCE adapter. |
| `CVE-2026-123634` | Runtime DNS resolution with subrequests | ASAN UAF and custom-debug crashes; no stock-image crash or unified RCE adapter. |
| `CVE-2026-121810` | HTTP/3 with upstream proxying | Not reproduced. |
| `CVE-2026-113425` | Mail proxy with `auth_http` | UAF and pristine worker crash reproduced; no unified RCE adapter. |

A worker crash, sanitizer report, allocation reuse, or client dispatch message is not command execution. RCE requires an independently created marker and a patched negative control.

## Full RCE evidence

Censys reproduced Rapid7's complete `CVE-2026-123007` exploit chain against an isolated nginx 1.31.8 target on native x86-64 AVX512 hardware. The run dispatched 119.02 GiB of plaintext over 16 auxiliary connections in 166.04 seconds, captured a 14,393-byte memory disclosure, resolved ASLR, reclaimed the overwritten pool, and dispatched a cleanup callback invoking `system(command)`.

The harmless command was:

```sh
touch /tmp/rapid7-nginx-h2-proof-01
```

An independent check found the marker owned by UID/GID 101:101, proving command execution as the nginx worker. A worker then aborted on signal 6 after a double free. This was not host root, a kernel exploit, container escape, or a stable shell.

See:

- [RCE evidence](evidence/cve-2026-123007/RCE-CONFIRMED.md)
- [Fresh release validation](evidence/release-validation/VALIDATION.md)
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
