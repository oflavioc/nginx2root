# TLS vs h2c calibration: a negative-results matrix for the CVE-2026-123007 accounting differential

> **A TLS negative is not patch status.** A defender who probes CVE-2026-123007 over TLS, sees nothing, and concludes "patched" produces the worst outcome this method can cause: a false reassurance about a host that may be fully affected. The active accounting differential separates nginx 1.31.8 from 1.31.9 over cleartext h2c only. Over TLS it does not, and the failure is silent.

This document is a first-class deliverable, not a footnote. It is built entirely from our own disposable local-lab runs (loopback only, on nginx images we own) so that anyone reusing the compact PoC understands exactly where its oracle is trustworthy and where it lies. Every cell below is lab-verified first-hand unless its confidence column says otherwise. We use three-valued logic throughout: a run is `DISCRIMINATES` (a real per-build verdict), `NON-SPECIFIC` (the same signal on both builds, so the verdict is `unknown`), or `INCONCLUSIVE` (the probe precondition was never met, so again `unknown`).

## What the probe actually measures

The compact probe consumes the initial connection window, queues roughly 8 MB of response, resets the stream, then sends a one-byte connection-level `WINDOW_UPDATE(0,1)` and a `PING "POC-SYNC"`. Its positive signature is a **PING-ACK with no preceding `GOAWAY(FLOW_CONTROL_ERROR)` and no connection close**. The intended reading is that the affected build accepted an over-credit update that the patched build rejects via its `send_queued`-aware bound (the fix in commit `e27f5fa84f`).

The signature is weaker than that reading. A PING-ACK proves the connection was still alive and responsive when the PING was processed. It does not, on its own, prove the send window was corrupted or that any accounting invariant was violated, because PING is not flow-controlled. We therefore treat the signature as **liveness after the probe sequence**, and we trust it as a vulnerability verdict only when a same-transport patched control reaches the opposite outcome in the same run. That control is what h2c provides and TLS does not.

## Primary calibration matrix

Build pair throughout: `nginx:1.31.8` (affected, image `793a5e7fb63b`) versus `nginx:1.31.9` (patched control, image `81b01f35f484`), built identically (four workers, `http2 on`, an 896-byte index and an 8,388,608-byte `big.bin`), driven by the frozen `python:3.10` client (CPython 3.10.22, OpenSSL 3.5.7). "Read discipline" is how the client drains the socket during setup; "draining" reads until block or EOF, "zero-window" stops reading to force TCP backpressure, "multistream" opens several concurrent streams instead of the single post-RST sequence.

| Transport | Read discipline | SO_RCVBUF | 1.31.8 (affected) | 1.31.9 (patched control) | Net result | Confidence |
| --- | --- | --- | --- | --- | --- | --- |
| h2c | draining | 8K through 4M (any tested) | Over-credit: one-byte update accepted, PING-ACK, no GOAWAY, no close | Closes at the 4 MiB refund `WINDOW_UPDATE`; logs `client violated connection flow control`; probe never sent | **DISCRIMINATES** (true positive vs true negative) | High, lab-verified |
| h2c | zero-window | 32K | Over-credit: PING-ACK on the stalled connection | Closes after the 4 MiB refund | **DISCRIMINATES** | High, lab-verified |
| h2c | multistream | any | Positive signature | Positive signature | **NON-SPECIFIC** (false positive on patched) -> verdict `unknown` | High, lab-verified |
| TLS | draining | 8K through ~1.5M | Inconclusive: fewer than 4 MiB of DATA flows, the 4 MiB refund is rejected, the one-byte probe is never reached | Inconclusive: same | **INCONCLUSIVE** (false-negative region) -> verdict `unknown` | High, lab-verified |
| TLS | draining | ~2M through 4M | Over-credit signature (PING-ACK, no GOAWAY) | Over-credit signature (PING-ACK, no GOAWAY) | **NON-SPECIFIC** (false positive on patched) -> verdict `unknown` | High, lab-verified |
| TLS | zero-window | 32K through 256K | Closes | Closes | **NON-SPECIFIC** (false negative on both) -> verdict `unknown` | High, lab-verified |

Reading the table: there is no row in the TLS half where 1.31.8 and 1.31.9 land on opposite outcomes. Every tested TLS condition is either a false-negative region (both look patched) or a false-positive region (both look affected). A scanner that reports a TLS verdict in any of these conditions is reporting noise.

## The DATA-volume sweep that drives the TLS failure

The discriminator depends on more than 4 MiB of response DATA remaining queued when the refund update arrives. Over TLS the amount of DATA the client observes is governed by `SO_RCVBUF` and read discipline, not by the server's internal queue, so the precondition flips from unmet to over-met with no window in between. Client-observed DATA for the affected (1.31.8) build over TLS, draining:

| SO_RCVBUF | DATA received (TLS, 1.31.8) | 4 MiB refund outcome | Region |
| --- | --- | --- | --- |
| 8K | ~270 KB | Rejected (precondition unmet) | False-negative |
| 256K | ~2.37 MB | Rejected (precondition unmet) | False-negative |
| 1M | ~3.22 MB | Rejected (precondition unmet) | False-negative |
| 2M | ~8.13 MB | Accepted, over-credit signature | False-positive |
| 3M | ~8.13 MB | Accepted, over-credit signature | False-positive |
| 4M | ~8.13 MB | Accepted, over-credit signature | False-positive |

Over h2c the discriminator fires at the same ~8.13 MB of flowed DATA, but there the patched build still closes at the refund while the affected build accepts it. The transport is the only thing that changed. The jump from 1M (3.22 MB, rejected) to 2M (8.13 MB, accepted) is a coarse step and we did not sample the roughly 1 MiB interval between them densely, so we state the narrow truth: **none of the receive-buffer settings we tested yielded a patched-versus-affected separation over TLS.** We do not claim mathematically that no setting could.

## Corroborating direct-TLS evidence

In the direct-loopback final matrix both TLS builds closed at the refund update, but their server logs record different effective windows, which is itself a fingerprint of the patch and a reminder that a close is not a verdict:

- 1.31.8 (affected): `window increment 4194304 not allowed for window 2144272383`
- 1.31.9 (patched): `window increment 4194304 not allowed for window 2144313391`

The 41,008-byte difference is consistent with the patched build including queued response bytes in its accounting, exactly what commit `e27f5fa84f` adds. It does not complete a vulnerable positive, because on the affected build the 4 MiB update exceeded the queued bytes and the client never reached `RST_STREAM`. Separately, over Docker's host-network published TLS port both builds returned exit 0 with a PING-ACK and both logged 8,060,805 bytes sent for `big.bin`: a clean patched-control false positive. Source records: `evidence/release-validation/compact-avx512-vm/RESULTS.md`, `evidence/release-validation/compact-avx512-vm/results.json`, `evidence/release-validation/tls-oracle-matrix.csv`.

## The positive signature is liveness, and the mechanism is unproven

Two honesty constraints bound every claim here.

First, the PING-ACK-without-GOAWAY signature is **liveness, not a corrupted-window proof.** We never observed the server-side send window or queue state directly; we inferred behavior from client-visible frames. Calling the one-byte update "over-credit" is an interpretation of that signature, sound only where a same-transport patched control rejects in the same run.

Second, the explanation for *why* TLS defeats the differential, that queued bytes migrate into the SSL/socket write path and leave the patched build's `send_queued`-aware bound with nothing to reject, is an **unproven hypothesis, not a demonstrated mechanism.** Confirming it would require instrumenting nginx (debug logging or a debugger) to read the send window and the queued-frame chain at the instant the refund update is processed over each transport. We have not done that. Identical client-observed DATA totals do not imply identical internal queue states, and the behavior could instead be an interaction with the Python `ssl` client's read-ahead and buffering rather than an inherent property of nginx over TLS. We mark the mechanism `unknown`.

## What the cross-vendor review changed

An independent adversarial review (Gemini and OpenAI, run in refute mode) hardened this document rather than softening the conclusion. It forced three corrections that are now reflected above:

1. The oracle wording moved from "answers a PING" to "answers a PING with no `GOAWAY(FLOW_CONTROL_ERROR)` and no close", because a bare FIN or a PING-ACK flushed alongside a GOAWAY would otherwise be misread.
2. The central claim narrowed from "TLS cannot discriminate at any receive buffer" to "none of the receive-buffer settings we tested discriminated", and the SSL-queue-migration mechanism was demoted to an explicit hypothesis.
3. The earlier "production fronting degrades the differential" story was corrected but not inverted: the same ambiguity reproduces on clean, unfronted lab TLS, so fronting is **not required** to break the probe, but that does not prove fronting was absent or harmless in production. HTTP/2-terminating proxies and CDNs independently prevent client flow-control frames from reaching the origin, so both factors can hold at once. The production cause remains `unknown`.

## Scope and the three-valued honesty rule

This matrix speaks only to the two builds and the configuration we ran. We do not extend a TLS result to any build, distro, or product we did not test. For CVE-2026-123007 the banner already lies under Ubuntu's backport (USN-9159-1 keeps the identical `nginx/1.18.0 (Ubuntu)` string), and here we show the active TLS differential lies too. Distros and products we did not verify (Debian, RHEL family, Alpine, Amazon Linux 2023, Chainguard, OpenResty, ingress-nginx, Kong, Tengine, NGINX Plus) stay `unknown`, and their only reliable check is on-host, not on the wire.

## Conclusion: how to actually get a verdict

Do not trust a TLS result from this probe, positive or negative. In order of reliability:

1. **Use cleartext h2c** where the service exposes it. That is the only transport where the probe produced a per-build verdict in our lab, and even then only with the single-connection post-RST sequence, never the multistream variant.
2. **Carry a known-patched control on the same transport and run.** If the control does not reach the opposite outcome, the run is non-specific and the verdict is `unknown`, by construction, regardless of what the target did.
3. **Prefer on-host package inspection** as the authoritative check, since the banner and the TLS differential are both unreliable remotely:
   - Debian and Ubuntu: `dpkg -l nginx-core` (and `nginx -V` for the build config)
   - RHEL family (Alma, Rocky, and derivatives): `rpm -q nginx`
   - Alpine: `apk info nginx`

A remote TLS "nothing happened" is `unknown`. Treat it as such.
