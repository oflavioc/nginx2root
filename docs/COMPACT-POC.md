# Compact `CVE-2026-123007` h2c PoC

**One file. No third-party Python packages. No RCE.**

[`h2c_flow_control_test.py`](../h2c_flow_control_test.py) is the Censys compact accounting test represented by the retained **5.69 MB vulnerable** and **1.41 MB patched** h2c captures. It demonstrates different behavior between vulnerable nginx 1.31.8 and patched 1.31.9 without generating the 60–119 GiB traffic schedules used by Rapid7's later crash and RCE stages.

See the [vulnerable-versus-patched diagram](../docs/CVE-2026-123007-ATTACK-CHAIN.md).

## Run the complete differential

Requirements: Docker with `nginx:1.31.6`, `nginx:1.31.7`, `nginx:1.31.8`, and `nginx:1.31.9` images, and Python 3.10 or newer. Use a disposable lab you own. The default `--versions 1.31.8,1.31.9` pair requires only those two images.

```sh
uv run python -I h2c_flow_control_test.py \
  --docker \
  --output /tmp/nginx2root-compact-evidence.json \
  --command-timeout 45 \
  --client-timeout 45 \
  --acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB
```

The script creates an internal Docker network, starts each target, runs the client in a separate container sharing the target's network namespace, and removes the containers and network afterward. It uses no host networking or published ports. It accepts only numeric loopback targets and requires the exact acknowledgement above.

`--command-timeout` and `--client-timeout` are each capped at 120 seconds. The target containers have memory, PID, capability, and `no-new-privileges` restrictions. The JSON evidence records the script SHA-256, image versions, expected and actual exit codes, result summaries, and whether cleanup was attempted.

Expected final result:

```text
PASS: vulnerable h2c accepted over-credit; patched control rejected it
```

The command exits zero only when vulnerable 1.31.8 accepts the one-byte update and returns `POC-SYNC` PING acknowledgment, while patched 1.31.9 rejects the earlier 4 MiB update and closes before the probe.

## Expanded version matrix

The compact accounting differential has been verified on **1.31.6, 1.31.7, and 1.31.8**, with **1.31.9** as the rejecting patched control. Run all four:

```sh
uv run python -I h2c_flow_control_test.py \
  --docker \
  --versions 1.31.6,1.31.7,1.31.8,1.31.9 \
  --output /tmp/nginx2root-compact-matrix-evidence.json \
  --acknowledge-local-lab I-AUTHORIZE-LOCAL-LAB
```

This expands the version coverage of the compact test only. It does not establish RCE compatibility on those versions. Full RCE is separately verified on 1.31.6 and 1.31.8 with Rapid7's matched profiles; 1.31.7 RCE remains unverified.

## What the client does

1. Consumes the connection's initial 65,535-byte window with small responses.
2. Raises the connection window to the HTTP/2 maximum.
3. Requests an 8 MB file and stops reading, leaving response DATA queued.
4. Sends a 4 MiB connection-window update, then resets the response stream.
5. Sends a one-byte update. Vulnerable nginx accepts it after over-crediting.
6. Sends PING. The acknowledgment proves the connection remains alive.

Patched nginx rejects the earlier 4 MiB update and closes with TCP FIN. Its server log records `client violated connection flow control`.

## What it does not do

The compact test does not corrupt memory, reclaim heap objects, install a callback, execute a command, or create a shell. The full RCE implementation is Rapid7's separate public exploit, linked in [`third_party/README.md`](../third_party/README.md).

## TLS status

The client has a `--tls` option for continued testing, but the compact sequence is **not validated over TLS**. Do not describe TLS support as confirmed. The original packet captures are cleartext h2c.

## Run only the offline tests

```sh
uv run pytest tests/test_compact_flow.py
```

These tests cover frame parsing, result classification, and target guards without contacting a target.

## Evidence

The original positive and negative captures are in [`evidence/cve-2026-123007/`](../evidence/cve-2026-123007/). They contain private lab addresses, stock nginx content, and the `POC-SYNC` PING, with no personal information or credentials.
