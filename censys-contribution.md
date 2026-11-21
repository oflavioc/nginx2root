# Censys-Research Contribution: CVE-2026-123007 Empirical Calibration

## What this contributes (built entirely from executed lab evidence)

This contribution extends the Censys-Research `h2c_flow_control_test.py` compact PoC with empirical calibration data from an independent reproduction across nginx 1.18.0-1.31.9, including the Ubuntu backport series. All claims below are backed by artifact SHAs in the evidence corpus.

### 1. 72-cell worker x heap x version compatibility matrix

**Result:** 63/63 positives across seven tested versions (1.30.0, 1.30.6, 1.31.0, 1.31.5, 1.31.6, 1.31.7, 1.31.8), 9/9 negatives (1.31.9 control), 72/72 test cells met expectation (7 versions × 3 worker counts × 3 heap states = 63; 1 control × 3 × 3 = 9). Worker count (1/2/4) and heap pressure (fresh/40/200 prior requests) make zero difference to the accounting outcome.

**Artifacts:**
- `worker-heap-matrix.csv` (SHA-256 `765ded3355bfcfee9dd48f6b4838b998e0181816eade4883548f78b91a3742d9`)
- `worker-heap-results.json` (SHA-256 `1d2ec6c9c92b052b4c365b102fb7ceb2c168193500632dc869d4ac181f8bab22`)

**Scanner implication:** no classification differences were observed across configured worker counts (1/2/4) and request-history counts (0/40/200) in this setup. These runs required no additional grooming beyond the documented probe sequence.

### 2. `upstream-short` false-negative precondition trap

**Finding:** when the response is too small to leave >=4 MiB queued in `h2c->last_out`, a genuinely vulnerable server correctly rejects the 4 MiB `WINDOW_UPDATE` — not because it's patched, but because the attack precondition was never met. The `upstream-short` rows show `queued_bytes_lower_bound` of ~3.18 MiB, below the 4 MiB threshold.

**Artifact:** `response-matrix.csv` (in `evidence/release-validation/`)

**Scanner implication:** a negative result is only meaningful when the queued-byte precondition is verified. A scanner that probes against a small response and reads the rejection as "patched" will miss vulnerable hosts. Measure the queued-byte lower bound before trusting a negative.

### 3. Client exit-code and "INCONCLUSIVE" classification defect

**Finding:** the compact client (a) prints later-stage headings unconditionally, so a patched server that closes early gets mislabeled "INCONCLUSIVE" instead of "rejected"; (b) exits 0 on some non-confirmed paths. Both lead to false classifications in automated pipelines.

**Fix applied in our matrix:** relabel `closed before probe` as expected patched-control behavior; preserve original client text in a `detail` column. The independent oracle (PING-ACK on corrupted window) is the proof, never the client's exit code.

**Scanner implication:** the patched-side classification is where false positives are born. Build the negative control into the oracle logic, not the exit code.

### 4. On-wire `send_queued` signature (window-delta signal)

**Finding:** patched 1.31.9 reports in its rejection log an effective window that includes `send_queued`:
```
window increment 4194304 not allowed for window 2145239073
```
where `2145239073 = 0x7fffffff - 2244574`. That ~2.1 MiB reduction is the `send_queued` term. Vulnerable builds accept the same update and answer PING.

**Frame-level differential:**
- Positive (1.31.8): RST_STREAM(157) -> accepted WU(0,1) -> PING-ACK; no GOAWAY
- Negative (1.31.9): connection FIN after 4 MiB WU; none of the RST/accepted-WU/PING frames

**Artifacts:** `oracle-v2-positive.pcap` (701 pkts), `oracle-v2-negative.pcap` (585 pkts)

### 5. Ubuntu 1.18.0 backport calibration — same banner, opposite behavior, serving-mode trap

**Empirically proven** (3 version-matched builds, `D:\NexaLab\scenarios\nginx2root\ubuntu-backport-proof.md`):

**Static serving:**
| Build | Banner | Oracle | Verdict |
|---|---|---|---|
| upstream `nginx:1.18.0` | `nginx/1.18.0` | HANG | vulnerable |
| Ubuntu `1.18.0-6ubuntu14` (pre-patch) | `nginx/1.18.0 (Ubuntu)` | HANG | vulnerable |
| Ubuntu `1.18.0-6ubuntu14.24` (post-USN-9159-1) | `nginx/1.18.0 (Ubuntu)` | ConnectionReset | PATCHED |

Identical banner, opposite behavior. Pre-patch control confirms the change is the USN fix, not a distro quirk. Patched manifestation differs from mainline: 1.31.9 = RuntimeError; Ubuntu backport = TCP-reset.

**Proxied serving (the trap):**
Both unpatched AND backport-patched 1.18.0 accept the over-credit under proxied serving — the same precondition mechanism as item 2: proxy buffering does not accumulate enough queued bytes to trigger the rejection threshold (RFC 9113 §6.9 / RFC 7540 §6.9 requires acceptance when `send_window + send_queued + increment <= 0x7fffffff`). The behavioral differential **cannot separate patch levels in this mode** with the default 4 MiB probe parameters.

**Scanner implication:** for the 1.18.0 series with the tested probe parameters, behavioral probing is reliable only under static serving. Under proxied serving (the common production case), the probe cannot distinguish patched from unpatched. Operators should rely on authenticated package verification (`dpkg -l nginx-core` >= `1.18.0-6ubuntu14.23`) to establish patch status.

### 6. Version-fingerprint backport blind spot (now empirically confirmed)

The version-range fingerprint (`>=1.9.5 <1.30.7 || >=1.31.0 <1.31.9`) was validated at boundaries. **The structural gap is now empirically proven:** Ubuntu's USN-9159-1 patches `1.18.0-6ubuntu14.23`/`.24` while keeping the identical `nginx/1.18.0 (Ubuntu)` banner. A version-string scanner flags every such host as vulnerable — a confirmed false positive. Version detection is a triage signal, not a verdict.

### 7. Multi-stream mass is a false-positive trap

The multi-stream variant (90 streams x ~94 KiB each) shows OVER-CREDIT on **both** 1.31.8 (vulnerable) and 1.31.9 (patched). The multi-stream approach shifts the queued/sent ratio so delivered bytes exceed the probe threshold on both builds (RFC 9113 §6.9 / RFC 7540 §6.9 correct behavior). Do not use multi-stream mass as a vulnerability discriminator.

### 8. Validated Suricata detection rules

Rule pack SHA-256 `70d9dff9cc030ec93ae532bb01d2d08be846ecc8c3de31580f11844980857fce`:
- SIDs 9007013-9007015 (flowbits-linked oracle chain): fires exactly once on positive PCAP, zero on negative
- SIDs 9007010/9007011 (Rapid7 bootstrap): synthetic-only validated (no real TLS carrier capture — the KeyUpdate flight deadlocks in emulation)

### 9. TLS path: NOT validated

The compact differential is cleartext h2c only. The `--tls` option exists but we make no claim it works. Any TLS-path detection is unvalidated until a real capture exists.

### 10. Production probing — run-to-run variance

5 runs against government VDP production hosts (`nginx/1.18.0 (Ubuntu)`) showed **run-to-run behavioral variance** (accept / reject / RST) on the same target, matching no single lab control. Consistent with multiple edge backends or LB-dependent accounting. This is itself a documentable finding: the clean lab differential degrades against real-world fronted infrastructure.

## What this does NOT contribute

- **No novel bug.** Five reviewed accounting paths (stream-window refund, SETTINGS INITIAL_WINDOW_SIZE delta, send_chain deductions, partial-flush refund, and send_queued double-count) revealed no bypass or residual defect beyond CVE-2026-123007.

## Suggested contribution format

The honest pitch to Censys-Research is sections 1-10 above: the executed mainline matrix, the three oracle traps (false-negative from short responses, false-positive from classification defects, serving-mode blindness for the 1.18 backport series), the on-wire send_queued signature, the empirically confirmed backport blind spot, the multi-stream false-positive trap, and the production variance finding. All are reproducible from the cited artifacts and SHAs.
