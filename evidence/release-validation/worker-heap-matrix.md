# Worker and heap compatibility: CVE-2026-123007 accounting PoC

Completed: 2026-11-19T05:22:15.709654+00:00

## Scope and method

One attempt in one fresh container per version/worker/heap combination; 72 combinations total. Official linux/amd64 nginx images and the existing `/tmp/compact-current.py` client ran on the GCP `nginx2root-avx512` VM in `us-central1-a`. The client SHA-256 was `9417718625a82d47315e18149880c3392de1270b73ee04259b71b2ffbe9fbb9c`. Image IDs are recorded in `matrix.csv`.

Each target used `--network none`, no published ports, h2c on port 80, `http2 on`, `sendfile on`, `worker_connections 1024`, and a fresh 8 MiB `big.bin`. The accounting client and readiness/background helper shared only the target container's loopback namespace. This is an accounting test, not an RCE test.

Heap states: `fresh` has no background traffic; `40` and `200` are that many sequential, complete `GET /index.html` requests, one newly opened and closed h2c connection per request, completed before the accounting client. One readiness request precedes the background state. The final access-log count of 75 plus the background count checks readiness, all background requests, and all 74 accounting fill responses (73 full responses and one range response). Multi-worker distribution is kernel/load-balancer dependent and was not measured per worker.

Limits: one attempt per case and a 105-second combined cap for readiness, background generation, and the accounting client (45-second client allowance plus 60-second background allowance). Docker commands have a 45-second timeout. No retries replace negative or inconclusive outcomes.

## Matrix

`accepted + PING ACK` means the one-byte update was accepted, no GOAWAY or TCP close was observed, and the subsequent PING was acknowledged. No GOAWAY or TCP close was observed in those cases. `closed before probe` means the patched target closed during the preceding 4 MiB queued-byte update, so the one-byte probe was never sent; this is the expected patched control behavior, not a missing result. The original client still labels this `INCONCLUSIVE` because its later stage headings print unconditionally; `detail` in `matrix.csv` preserves that original text.

| Version | Workers | Fresh | 40 requests | 200 requests | Combined client seconds (fresh / 40 / 200) |
|---|---:|---|---|---|---|
| 1.30.0 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.896 / 22.188 / 35.488 |
| 1.30.0 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.907 / 22.231 / 35.34 |
| 1.30.0 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.942 / 22.263 / 35.334 |
| 1.30.6 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.899 / 22.196 / 35.312 |
| 1.30.6 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.903 / 22.19 / 35.307 |
| 1.30.6 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.912 / 22.193 / 35.505 |
| 1.31.0 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.943 / 22.236 / 35.395 |
| 1.31.0 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.929 / 22.24 / 35.329 |
| 1.31.0 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.93 / 22.187 / 35.313 |
| 1.31.5 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.921 / 22.271 / 35.337 |
| 1.31.5 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.932 / 22.211 / 35.395 |
| 1.31.5 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.931 / 22.214 / 35.322 |
| 1.31.6 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 19.197 / 22.235 / 35.436 |
| 1.31.6 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.947 / 22.226 / 35.363 |
| 1.31.6 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.932 / 22.195 / 35.334 |
| 1.31.7 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 19.087 / 22.224 / 35.313 |
| 1.31.7 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.932 / 22.242 / 35.38 |
| 1.31.7 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.928 / 22.381 / 35.33 |
| 1.31.8 | 1 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.943 / 22.224 / 35.373 |
| 1.31.8 | 2 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.963 / 22.212 / 35.313 |
| 1.31.8 | 4 | accepted + PING ACK | accepted + PING ACK | accepted + PING ACK | 18.916 / 22.206 / 35.312 |
| 1.31.9 | 1 | closed before probe | closed before probe | closed before probe | 10.887 / 14.169 / 27.297 |
| 1.31.9 | 2 | closed before probe | closed before probe | closed before probe | 10.882 / 14.173 / 27.334 |
| 1.31.9 | 4 | closed before probe | closed before probe | closed before probe | 11.062 / 14.184 / 27.315 |

## Outcome totals

- `negative_closed_before_probe`: 9
- `positive`: 63
- Expectations met: 72/72
- Completed readiness and background sequences: 72/72
- Expected request totals observed: 72/72
- Containers removed: 72/72

## Timing constraints

The client intentionally sleeps for about 3.66 seconds while granting stream credit and has stage-specific drains of 0.25-3 seconds. Background generation adds time before the accounting stages, so the table reports the combined readiness/background/accounting wall time. These single-attempt results show compatibility under the tested conditions, not a reliability estimate or proof of later exploitation.

Raw per-case client and nginx logs, background logs, and result JSON remain on the VM in `/tmp/worker-heap-matrix/cases/`. The machine-readable aggregate is `results.json` here.
