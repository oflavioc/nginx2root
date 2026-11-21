# `CVE-2026-123007` on-host crash and failure-mode detection

This pack detects the **failure** that the nginx2root HTTP/2 flow-control over-credit (`CVE-2026-123007`, CWE-191) produces on a host, not the exploit that caused it. The confirmed end state of Rapid7's full chain against a vulnerable build is a worker that aborts and exits (an availability event). This document gives on-host log, service, orchestration, and core-dump signals for that end state, plus one network behavioral rule framed as a failure-mode precursor.

It is complementary to the network oracle rules the repository already ships for **captured PoC traffic** (Suricata SIDs `9007013`-`9007015`, the flowbits-linked RST then WINDOW_UPDATE(0,1) then PING chain, validated to fire exactly once on `evidence/cve-2026-123007/oracle-v2-positive.pcap` and zero times on `oracle-v2-negative.pcap`). Those rules need the discriminating frames on the wire and were only validated over cleartext h2c. This file adds the **on-host crash signal, which did not exist before**, so a defender who cannot see decrypted HTTP/2 frames still has something to alert on.

## Honesty contract (read before using any verdict here)

Patch status is reported with three values: **vulnerable**, **not-affected**, **unknown**. We never collapse `unknown` into a guess.

- A banner in the affected range is a **candidate**, never a verdict. Ubuntu backports the fix while keeping the identical `nginx/1.18.0 (Ubuntu)` banner (lab-verified: `1.18.0-6ubuntu14` is vulnerable, `1.18.0-6ubuntu14.24` is patched, same banner, same HTTP/2 SETTINGS). See `evidence/cve-2026-123007/ubuntu-backport-proof.md`.
- The remote active TLS differential does **not** discriminate patched from vulnerable (`evidence/release-validation/tls-oracle-matrix.csv`). The compact h2c accounting differential discriminates only over cleartext h2c.
- The only reliable patch check is **on-host**: the installed package revision and the running build config. That is Section A.
- A crash signal (Section B) tells you a worker **failed in a way consistent with this class**. On its own it is not proof that `CVE-2026-123007` was the cause. Confidence is raised by correlating the crash with the HTTP/2 code path (core-dump backtrace) and with a vulnerable, unpatched build on the same host.
- Distros and products we did **not** lab-verify are marked `unknown` with the on-host method stated. We do not invent advisory IDs or fixed version strings for them.

Verified fix points we rely on: upstream nginx **1.30.7** (stable) and **1.31.9** (mainline), fix commit **e27f5fa84f** (adds a `send_queued`-aware bound on the connection WINDOW_UPDATE). Affected range: **1.9.5-1.30.6** and **1.31.0-1.31.8**, HTTP/2 required. Ubuntu USN-**9159-1** backports the fix: Jammy 22.04 at package **1.18.0-6ubuntu14.23**, Focal 20.04 at **1.18.0-0ubuntu1.7+esm5** (needs ESM).

---

## Section A. On-host patch-status determination (the only reliable check)

### A.0 Precondition: is HTTP/2 even reachable?

The bug requires HTTP/2. If the build has no HTTP/2 module, or no listener enables it, the host is **not-affected by this vector** regardless of version.

```sh
# Is HTTP/2 compiled in? (upstream builds and most distros ship it, but confirm.)
nginx -V 2>&1 | tr ' ' '\n' | grep -E 'http_v2_module|http_v3_module'

# Is any listener actually serving HTTP/2? (directive form OR legacy "listen ... http2")
nginx -T 2>/dev/null | grep -nE '^\s*http2\s+on|listen[^;]*\bhttp2\b'
```

Reading: `--with-http_v2_module` present AND at least one `http2 on;` / `listen ... http2` means the vector is live. No HTTP/2 listener means the over-credit path is unreachable on this instance (still patch it, but it is not exploitable as configured).

### A.1 Package revision (authoritative where we have a fixed version)

| Platform | On-host command | Fixed at | Source / confidence |
| --- | --- | --- | --- |
| Ubuntu 22.04 (Jammy) | `dpkg -l 'nginx*' \| grep -E 'nginx-(core\|full\|light\|common)'` then `apt-cache policy nginx-core` | `1.18.0-6ubuntu14.23` (we also tested `.24`) | USN-9159-1; **lab-verified** by us (`.14` vulnerable, `.24` patched, same banner). High. |
| Ubuntu 20.04 (Focal) | same, with ESM enabled (`pro security-status`) | `1.18.0-0ubuntu1.7+esm5` | USN-9159-1 (authoritative). Not independently lab-reproduced at this exact revision. Medium. |
| Upstream nginx.org build | `nginx -v` | `1.30.7` or `1.31.9` | Upstream advisory + commit `e27f5fa84f`; **lab-verified** differential 1.31.8 vs 1.31.9. High. |
| Debian (non-Ubuntu) | `dpkg -l 'nginx*'` then compare against the Debian security tracker for CVE-2026-123007 | **unknown** | Not verified. Method stated. Do not assume Ubuntu revisions apply. |
| RHEL / Alma / Rocky | `rpm -q nginx` then `rpm -q --changelog nginx \| grep -iE '123007\|flow.control\|window'` | **unknown** | Not verified. Consult the vendor erratum; do not invent a version. |
| Amazon Linux 2023 | `rpm -q nginx` or `dnf info nginx`; `dnf updateinfo list \| grep -i nginx` | **unknown** | Not verified. Method stated. |
| Alpine | `apk info -v nginx`; `apk version -c nginx` | **unknown** | Not verified. Consult the Alpine secdb; do not invent a version. |
| Chainguard / Wolfi | `apk info -v nginx` inside the image | **unknown** | Not verified. Consult the image advisory. |

Resolve a Debian-family package to a three-valued verdict:

```sh
# Prints the exact installed revision; you compare it to the fixed revision for YOUR release.
dpkg-query -W -f='${Package} ${Version} ${Status}\n' 'nginx*' | grep -E 'nginx-(core|full|light)'
```

- Revision **>=** your release's fixed revision from the table above -> **not-affected**.
- Revision **<** that fixed revision, HTTP/2 live -> **vulnerable**.
- Release not in the table, or no published fixed revision found -> **unknown** (do not guess).

### A.2 Derivatives and repackagers (all `unknown` to this pack)

These ship their own nginx core on their own patch timelines. The upstream `1.30.7` / `1.31.9` numbers do **not** map cleanly onto them, and we did not verify any of them. Determine status from the product's own advisory plus the on-host build string.

| Product | On-host command | Verdict | Note |
| --- | --- | --- | --- |
| OpenResty | `openresty -V 2>&1` (shows bundled nginx core) | **unknown** | OpenResty releases lag upstream; check the OpenResty advisory, not the core number alone. |
| ingress-nginx (k8s) | `kubectl -n <ns> exec <pod> -c controller -- nginx -v` | **unknown** | The image tag pins the nginx build; check the ingress-nginx release notes for the fix. |
| Kong | `kong version` plus `nginx -V` inside the container | **unknown** | Kong bundles OpenResty/nginx; check the Kong advisory. |
| Tengine | `nginx -V 2>&1` (Tengine fork banner) | **unknown** | Separate Alibaba patch lineage; version mapping to upstream does not hold. |
| NGINX Plus | `nginx -v` (reports `nginx-plus-rNN`) | **unknown** | Commercial build; check the F5/NGINX security advisory for the fixed `rNN`. |

If you cannot obtain the product's own fixed version, the host stays **unknown**. An `unknown` host with HTTP/2 live and a crash signal from Section B should be treated as a priority to patch, not as a confirmed clean or confirmed vulnerable host.

---

## Section B. Crash and failure-mode signals (on-host)

The lab end state of the full chain on a vulnerable 1.31.8 build was a glibc heap-integrity abort followed by a worker exit on signal 6 (`SIGABRT`), single-shot. That is the primary signature below. A later disclosure stage can instead fault with signal 11 (`SIGSEGV`); we did not reach that stage in our environment, so it is listed as plausible-but-unverified.

### B.1 nginx error log: worker exited on signal (primary signal)

Lab-observed lines (from `evidence/cve-2026-123007/RCE-CONFIRMED.md`):

```text
free(): double free detected in tcache 2
2026/11/21 15:29:37 [alert] 1#1: worker process 22 exited on signal 6
```

The nginx master logs the worker exit to its configured `error_log`. nginx appends ` (core dumped)` to that line when the kernel wrote a core. The glibc line (`free(): double free detected in tcache 2`, or `malloc(): ...`, `corrupted ...`, `tcache ...`) is written by glibc to the worker's **stderr**, so where it lands depends on wiring: the systemd journal if `error_log` is `stderr` or nginx runs under systemd, container stdout/stderr (`docker logs` / `kubectl logs`) in a container, otherwise it may not reach the `error_log` file at all. Grep both places.

```sh
# Abnormal worker exits (signal 6 verified; 11 included as a plausible disclosure-stage fault).
grep -En 'worker process [0-9]+ exited on signal (6|11)( \(core dumped\))?' /var/log/nginx/error.log

# glibc heap-integrity aborts on stderr-wired logs.
grep -EnC2 'free\(\): |malloc\(\): |corrupted|tcache|double free' /var/log/nginx/error.log
```

```sh
# Systemd-managed nginx: the glibc stderr line and the exit line both land in the journal.
journalctl -u nginx --since "-2h" -g 'exited on signal (6|11)|free\(\): |double free|tcache'
```

**ngx_http_v2 context (confidence lift).** The crash line alone does not name the HTTP/2 path. Tie it to this CVE with a core-dump backtrace: the top frames of a core from this chain are in the HTTP/2 module (for example `ngx_http_v2_*` such as the filter-cleanup and output-queue paths that refund the queued credit). We did not capture a production backtrace, so the specific frame set is inferred from the source-level mechanism, not from a field core. Use Section B.5 to obtain a backtrace and look for `ngx_http_v2_` frames; their presence alongside a signal-6 abort is the strongest on-host attribution available without decrypted traffic.

### B.2 systemd service restart churn (secondary, often silent for this bug)

Be precise: an nginx **worker** crash does not normally restart the systemd unit. The master survives and re-forks the worker, so `Restart=` and `NRestarts` usually stay flat even while workers are aborting. Service-level churn fires only when the failure escalates (master death, a watchdog, or an operator restart). Treat a rising `NRestarts` as a stronger-but-rarer signal, and the re-forked-worker log lines in B.1 as the common case.

```sh
# Unit restart counter and last results. A climbing NRestarts means the whole service is flapping.
systemctl show nginx -p NRestarts -p Restart -p Result -p ExecMainStatus

# Service-level failure events (these appear only on escalation, not on a lone worker abort).
journalctl -u nginx --since "-6h" -g 'Main process exited|Failed with result|Scheduled restart|watchdog'
```

Reading: repeated `worker process ... exited on signal 6` with `NRestarts` unchanged is the expected shape of this bug (worker-only, master re-forks). `NRestarts` climbing, or `Main process exited, code=killed, status=6/ABRT`, means the crash took the master or a watchdog acted.

### B.3 Kubernetes ingress pod restartCount and exit codes

Same caveat as systemd: a single worker abort inside the pod usually does not bump `restartCount`, because the controller/master re-forks the worker. The count climbs when the crash cascades to container exit (liveness-probe failure or the controller process exiting). When it does climb, the terminated exit code is diagnostic: **134** is `128+6` (`SIGABRT`), **139** is `128+11` (`SIGSEGV`).

```sh
# Restart counts and last-termination reason/exit code for the ingress controller container.
kubectl -n ingress-nginx get pods -l app.kubernetes.io/component=controller -o \
  jsonpath='{range .items[*]}{.metadata.name}{"\t"}{range .status.containerStatuses[*]}{.name}={.restartCount} last={.lastState.terminated.reason}/{.lastState.terminated.exitCode}{" "}{end}{"\n"}{end}'

# The crash text from the previous container instance (where the glibc abort line lives).
kubectl -n ingress-nginx logs <pod> -c controller --previous 2>/dev/null \
  | grep -En 'exited on signal (6|11)|free\(\): |double free|tcache'
```

Reading: `lastState.terminated.exitCode` of `134` or `139` on the ingress controller, especially recurring, is a container-level view of the same worker-abort failure. `restartCount` flat while `kubectl logs` shows the abort lines is the worker-only case.

### B.4 Upstream 502 bursts (corroborating, high false-positive)

When a worker aborts mid-response, in-flight requests on that worker fail. For a reverse proxy or ingress this surfaces as a burst of `502` (and client-side resets / `499`) aligned in time with a B.1 crash line. A 502 burst on its own is weak: deploys, upstream restarts, and backend outages all produce it. Use it only to corroborate a crash line within the same time window.

PromQL (metric names depend on your exporter; `nginx_ingress_controller_requests` is the ingress-nginx controller metric, adjust for the Prometheus nginx exporter or VTS):

```promql
# 502 rate spike on the ingress.
sum(rate(nginx_ingress_controller_requests{status="502"}[1m])) by (ingress) > 0

# Tie it to worker restarts if you export process_start_time or a restart counter:
# a 502 burst within ~60s of a worker (re)start is the shape to alert on, not 502 alone.
```

Access-log fallback (field index depends on your `log_format`; `$status` is field 9 in the stock `combined` format):

```sh
# Count 502s in the last ~2 minutes and correlate the timestamp against error.log crash lines.
awk '$9=="502"{c++} END{print c" responses with status 502"}' /var/log/nginx/access.log
```

### B.5 Core-dump and OOM watchers (plus a discriminator)

**Core dumps.** If core dumps are enabled, a core from this chain is an `SIGABRT`/`SIGSEGV` core for the nginx binary. The backtrace is what upgrades a generic crash to "HTTP/2 path" attribution (B.1).

```sh
# systemd-coredump hosts:
coredumpctl list /usr/sbin/nginx
coredumpctl info COREDUMP_SIGNAL=6 /usr/sbin/nginx        # SIGABRT cores
coredumpctl gdb <PID> <<<'bt'                              # look for ngx_http_v2_* top frames

# Non-systemd hosts: find where cores go, then confirm one exists.
cat /proc/sys/kernel/core_pattern
ls -la ${NGINX_WORKING_DIR:-/var/cache/nginx}/core* 2>/dev/null
```

**OOM is a discriminator, not this signal.** This crash is a heap-integrity abort, not memory exhaustion: the lab run recorded no kernel OOM-killer events and bounded memory by design (`evidence/cve-2026-123007/REPORT.md`). So an OOM event points **away** from `CVE-2026-123007`. Watch for it precisely to rule it out: a worker killed by signal 9 with an `oom_kill` record is a different problem.

```sh
# Kernel / cgroup OOM events. Presence here argues for a DIFFERENT root cause (not this CVE).
journalctl -k --since "-2h" -g 'oom_kill|Out of memory|Killed process'
dmesg --ctime | grep -iE 'oom|killed process' | tail
# cgroup v2 per-service OOM counter (0 for this bug's signature):
cat /sys/fs/cgroup/system.slice/nginx.service/memory.events 2>/dev/null | grep -E 'oom(_kill)?'
```

Discriminator summary: signal **6** or **11** with **no** `oom_kill` is consistent with this class; signal **9** / `oom_kill` present is a different failure.

### Quiet-baseline note

A healthy nginx emits **zero** `exited on signal` lines. Planned reloads (`SIGHUP`) and shutdowns log graceful messages (`gracefully shutting down`, `exiting`, `worker process ... exited with code 0`), never `exited on signal N`. So the alert threshold for B.1 is effectively **>=1 abnormal-signal exit in a rolling window** (for example 1 in 5 minutes), which is what makes this on-host signal high-value and low-noise. Before deploying, baseline your fleet for a day: if you see pre-existing `exited on signal 11` from an unrelated module or a flaky third-party module, record that rate and alert on deviation from it rather than on the first event. The glibc abort strings (`double free`, `tcache`, `malloc(): ...`) have no legitimate steady-state rate and can alert at >=1.

### Signal-to-meaning table

| Signal | What it shows | Confidence it is `CVE-2026-123007` | Main false-positive sources |
| --- | --- | --- | --- |
| B.1 `exited on signal 6` + glibc abort | Worker heap-integrity abort | **High** when the host is vulnerable/unknown and HTTP/2 is live; the lab-verified end state | Any other heap-corruption bug in nginx or a loaded module |
| B.1 `exited on signal 11` | Worker segfault (plausible disclosure-stage fault) | **Medium**, unverified by us | Unrelated nginx/module segfaults |
| B.1 ` (core dumped)` + `ngx_http_v2_*` backtrace | Crash located in the HTTP/2 path | **High** attribution lift | A different HTTP/2 bug in the same module |
| B.2 `NRestarts` rising / `status=6/ABRT` | Service escalated past worker-only | **Medium**; rare for this bug | Config errors, OOM of the master, operator restarts |
| B.3 exitCode `134`/`139`, recurring | Container-level view of the abort/segfault | **Medium-High** with B.1 text in `--previous` | Any crash-looping container cause |
| B.4 `502` burst | In-flight requests dropped by a crashing worker | **Low** alone | Deploys, upstream outages, backend restarts |
| B.5 core present, no OOM | Abort/segfault core, memory not exhausted | Corroborating | Other crash causes also leave cores |
| B.5 `oom_kill` / signal 9 | Memory exhaustion | **Argues against** this CVE | This is a different failure mode |

---

## Section C. One network behavioral rule (failure-mode precursor) plus a low-confidence liveness companion

These two rules are **new**. They **load cleanly under `suricata -T`** (signature/syntax validation passes, confirmed 2026-11-21 against `jasonish/suricata:latest`), but are **not yet validated against captured traffic** — loadable is not the same as proven to fire on real frames, and both carry `validated no` in their metadata until a pcap confirms them. They are distinct from the repository's shipped, validated oracle chain:

- Shipped and validated (captured PoC traffic, cleartext h2c): SIDs `9007013`-`9007015`, the precise RST then WINDOW_UPDATE(0,1) then PING flowbits chain. Use those when you have the PoC pcap.
- Below (this file): SID `9007016` behavioral precursor and SID `9007017` liveness corroboration, for live estates where you do not have the exact oracle frames. Treat them as tuning starting points, not as finished signatures. (SID `9007012` is intentionally left unused to avoid collision with the existing `9007010`-`9007015` block.)

Both rules match raw HTTP/2 frame bytes, so they only work over **cleartext h2c** (port 80 upgrade or prior-knowledge). Over TLS the frames are encrypted and invisible to Suricata, exactly as the remote active differential fails over TLS. On a TLS-only estate these rules will never fire, and the on-host signals in Section B are your detection.

### C.1 SID 9007016 — oversized connection WINDOW_UPDATE burst (behavioral, LOW confidence)

The failure-mode shape is many concurrent HTTP/2 streams carrying tiny DATA frames, combined with repeated oversized connection-level `WINDOW_UPDATE` deltas that drive the over-credit. A single large connection `WINDOW_UPDATE` is **normal** (high-throughput clients send them), so the distinctive element this rule keys on is a **burst** of large connection-level increments from one source. The stream-count and tiny-DATA-frame context cannot be expressed in one portable byte rule, so corroborate with the on-host crash line (Section B) and, if your Suricata build has HTTP/2 app-layer parsing, with a per-flow stream-count anomaly.

```suricata
# NGINX2ROOT CVE-2026-123007 failure-mode precursor (behavioral, h2c only, NOT validated against capture).
# Fires on a burst of connection-level (stream id 0) WINDOW_UPDATE frames with an increment >= 1 MiB.
# A single such frame is legitimate; the threshold is what makes this a precursor signal.
alert tcp any any -> $HTTP_SERVERS any ( \
    msg:"NGINX2ROOT CVE-2026-123007 precursor: oversized connection WINDOW_UPDATE burst over h2c (LOW confidence, behavioral)"; \
    flow:established,to_server; \
    content:"|00 00 04 08 00 00 00 00 00|"; \
    byte_test:4,>=,1048576,0,relative; \
    threshold:type threshold, track by_src, count 20, seconds 10; \
    flowbits:set,nginx2root.overcredit_precursor; \
    classtype:attempted-dos; \
    reference:cve,2026-123007; \
    metadata:cve CVE-2026-123007, signature_type behavioral, confidence low, validated no; \
    sid:9007016; rev:1; \
)
```

Tuning and honesty: this rule is a coarse volumetric heuristic. Expect false positives from legitimate high-throughput h2c clients and from load tests. Baseline your own `WINDOW_UPDATE` rates before enabling, raise `count` until steady-state traffic is quiet, and only escalate an alert when it coincides in time with a Section B crash line on the receiving host. It did not go through the pcap validation that `9007013`-`9007015` did, so it must not inherit their confidence.

### C.2 SID 9007017 — PING-ACK-without-GOAWAY liveness (VERY LOW confidence companion)

> **Loud warning.** Liveness alone is **all false positives** on any busy HTTP/2 estate. A server answering PINGs (PING-ACK) and not sending GOAWAY is the normal state of essentially every healthy h2 connection. This rule must **never** fire standalone. It is wired to require the C.1 precursor flowbit on the same flow, so it can only ever corroborate, not accuse. Do not re-weight it. Do not page on it. If you detach it from the precursor flowbit it becomes a noise generator.

In the validated oracle, the discriminating positive was the server answering PING after the RST then WINDOW_UPDATE(0,1) over-credit, with no GOAWAY: the connection stayed alive on a corrupted window. SID `9007015` already captures that precisely on PoC pcaps. The rule below is the loose, live-traffic shadow of it, gated behind the precursor so it is corroboration-only.

```suricata
# NGINX2ROOT CVE-2026-123007 liveness corroboration (VERY LOW confidence, corroboration-only).
# Server PING-ACK on a flow that ALREADY tripped the C.1 over-credit precursor. Standalone meaning: none.
alert tcp $HTTP_SERVERS any -> any any ( \
    msg:"NGINX2ROOT CVE-2026-123007 liveness: server PING-ACK after over-credit precursor (NOT proof, corroboration-only, high FP)"; \
    flow:established,to_client; \
    flowbits:isset,nginx2root.overcredit_precursor; \
    content:"|00 00 08 06 01 00 00 00 00|"; \
    threshold:type limit, track by_dst, count 1, seconds 60; \
    classtype:not-suspicious; \
    reference:cve,2026-123007; \
    metadata:cve CVE-2026-123007, signature_type liveness, confidence very-low, validated no; \
    sid:9007017; rev:1; \
)
```

A GOAWAY (frame type `0x07`) from the server after the precursor is the **opposite** signal: a patched or defending server rejects the oversized update and closes (the negative pcap ends in TCP FIN with no PING and no accepted over-credit). If you want to watch for the absence of a close, do it as analyst correlation, not as a paging alert.

---

## Section D. Putting a verdict together (three-valued)

1. Establish patch status on the host (Section A). Vulnerable, not-affected, or unknown. HTTP/2 not live anywhere means the vector is unreachable as configured.
2. Watch for the crash signature (Section B.1, primary): abnormal `exited on signal 6` with a glibc abort, ideally with an `ngx_http_v2_*` backtrace from a core (B.5).
3. Corroborate escalation and blast radius: `NRestarts` / exitCode `134`/`139` (B.2, B.3), time-aligned `502` bursts (B.4).
4. Rule out the look-alike: an `oom_kill` / signal 9 points at a different failure (B.5).
5. If decrypted or cleartext h2c traffic is available, the precursor rule (C.1) and the shipped oracle chain (`9007013`-`9007015`) add a network view. Over TLS, rely on Section B.

Honest outcome mapping:

- Vulnerable or unknown build + B.1 crash signature + HTTP/2 live -> **high-priority incident**: a failure consistent with `CVE-2026-123007` on a host that could be affected. Patch and investigate.
- Not-affected build (confirmed fixed revision) + B.1 crash signature -> investigate as a **different** crash; this CVE should not reproduce on a patched build.
- Unknown build + no crash signal -> **unknown**. Determine patch status on-host (Section A); do not infer clean or vulnerable from the banner or from the absence of a crash.

## References (verified only)

- Upstream fix: nginx 1.30.7 and 1.31.9, commit `e27f5fa84f` (`evidence/cve-2026-123007/e27f5fa84f.patch`).
- Lab crash signature: `evidence/cve-2026-123007/RCE-CONFIRMED.md` (`free(): double free detected in tcache 2`; `worker process 22 exited on signal 6`).
- Accounting-error confirmation and on-wire differential: `evidence/cve-2026-123007/REPORT.md`.
- Ubuntu backport, identical banner proof: `evidence/cve-2026-123007/ubuntu-backport-proof.md` (USN-9159-1; Jammy `1.18.0-6ubuntu14.24` patched).
- Validated network oracle chain for captured PoC traffic: SIDs `9007013`-`9007015` (see `evidence/cve-2026-123007/REPORT.md`, "Suricata validation outcome").
- TLS non-discrimination: `evidence/release-validation/tls-oracle-matrix.csv`.
