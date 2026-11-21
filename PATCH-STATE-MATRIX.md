# CVE-2026-123007 patch-state matrix

This is a consumer-facing reference for scanner vendors deciding how to classify an nginx target for `CVE-2026-123007` (nginx2root), the HTTP/2 flow-control send-window over-credit (CWE-191). It records only what we verified in the lab or can cite to an upstream source. Everything else is marked `unknown` with the exact on-host command that resolves it. Three-valued logic is used throughout: `vulnerable`, `not-affected`, `unknown`. There is no fourth "probably" state; a remote banner reading in the affected range is a `candidate`, which is a subtype of `unknown`, never a verdict.

**What this matrix is (and is not):** it records a banner-plus-package-revision *expected* state from vendor metadata — a triage input. It is never a claim that a given host's memory is actually corruptible, nor that the host is exploitable; both need on-host build inspection plus the gated RCE preconditions (matching golden profile + AVX-512). Key every row on the installed package revision, not the banner.

## Why a remote banner cannot decide patch state

The `Server` banner is not a reliable patch oracle for this CVE, and in the common distro case it is actively misleading.

1. Distributions backport the fix without changing the banner. Ubuntu ships the security fix under package `1.18.0-6ubuntu14.23` (Jammy) while the HTTP response header stays exactly `nginx/1.18.0 (Ubuntu)`. We lab-verified both ends of that backport on identical banners and identical HTTP/2 `SETTINGS` (see the Ubuntu rows below). So an `nginx/1.18.0 (Ubuntu)` banner is consistent with both a vulnerable host and a fully patched host. A banner reading inside the affected range is therefore a `candidate`, never `vulnerable`.
2. The active protocol differential does not generalize. The compact h2c accounting probe (see `h2c_flow_control_test.py`) discriminates vulnerable 1.31.8 from patched 1.31.9 only over cleartext h2c. Over TLS it does not discriminate, and sending it at all is the corrupting operation, so it is not a safe remote classifier. The only protocol-observable split requires firing traffic that is lab-only.
3. The banner can be absent. Many deployments emit a bare `nginx` with the version stripped, or a CDN or load balancer terminates HTTP/2 at the edge and hides the origin. In that case there is no version signal at all.

The sound conclusions a remote observer can draw are narrow:

- Banner reliably above the fixed version on a product that bumps its advertised version (upstream `>= 1.30.7` stable, `>= 1.31.9` mainline): `not-affected`.
- Banner reading inside the affected range on a product whose version is literal (upstream mainline or stable builds that do not backport under a frozen version): `candidate` (`unknown`, leaning vulnerable), needs on-host confirmation.
- Banner inside the affected range on a backporting distro (for example `nginx/1.18.0 (Ubuntu)`): `unknown`. The banner carries no fix information.
- Bare banner, stripped version, or CDN-fronted origin: `unknown`.

The correct remote value for any host we have not inspected on the box is `unknown`. The only reliable patch check is on-host: the package manager's installed version plus `nginx -V` for the build configuration. Each row below gives that command.

## Affected range (upstream, verified)

- Fixed upstream in nginx 1.30.7 (stable branch) and 1.31.9 (mainline branch). Fix commit `e27f5fa84f` adds a `send_queued`-aware bound on the connection-level `WINDOW_UPDATE`.
- Affected versions: 1.9.5 through 1.30.6, and 1.31.0 through 1.31.8.
- Precondition: the listener must serve HTTP/2. A pure HTTP/1.1 listener is not reachable by this bug.
- Source: nginx security advisories (https://nginx.org/en/security_advisories.html) and fix commit `e27f5fa84f`. Lab-verified in this repository on the mainline branch: 1.31.8 accepts the over-credit, 1.31.9 rejects it.

## Matrix

Columns: Distro / product | Banner string(s) | Packaged version(s) | Epoch / revision that carries the fix | Actual patch state | Confidence | How to verify on-host | Source.

### Verified rows

| Distro / product | Banner string(s) | Packaged version(s) | Epoch / revision that carries the fix | Actual patch state | Confidence | How to verify on-host | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| nginx upstream, stable branch | `nginx/1.30.x` (or a configured custom banner) | 1.9.5–1.30.7 | 1.30.7 | `vulnerable` if 1.9.5–1.30.6; `not-affected` if `>= 1.30.7` | High | `nginx -v` for the version, `nginx -V 2>&1` for the build config. No package manager needed for a source or vendor build. | nginx security advisories; fix commit `e27f5fa84f` |
| nginx upstream, mainline branch | `nginx/1.31.x` (or a configured custom banner) | 1.31.0–1.31.9 | 1.31.9 | `vulnerable` if 1.31.0–1.31.8; `not-affected` if `>= 1.31.9` | High | `nginx -v`, then `nginx -V 2>&1`. Lab-confirmed differential: 1.31.8 accepts the over-credit, 1.31.9 closes after the 4 MiB refund. | fix commit `e27f5fa84f`; this repo's lab differential (1.31.8 vs 1.31.9, cleartext h2c) |
| Ubuntu 22.04 LTS (Jammy) | `nginx/1.18.0 (Ubuntu)` (identical before and after the fix) | 1.18.0-6ubuntu14.x | 1.18.0-6ubuntu14.23 | `vulnerable` if the installed revision is below `-6ubuntu14.23`; `not-affected` at `>= -6ubuntu14.23` | High | `dpkg-query -W -f='${Version}\n' nginx-core` (or `nginx-common`), then compare the revision tail against `-6ubuntu14.23`. The banner does not move, so only the package revision decides. | USN-9159-1. Lab backport proof in this repo: `1.18.0-6ubuntu14` (pre-patch) is vulnerable and `1.18.0-6ubuntu14.24` (post-USN) is patched, on an identical banner and identical HTTP/2 `SETTINGS`. |
| Ubuntu 20.04 LTS (Focal) | `nginx/1.18.0 (Ubuntu)` (identical before and after the fix) | 1.18.0-0ubuntu1.7+esmX | 1.18.0-0ubuntu1.7+esm5 | `vulnerable` if below `+esm5`; `not-affected` at `>= +esm5`. The fix is delivered through ESM, so a host without Ubuntu Pro / ESM enabled stays vulnerable even when fully updated on the standard archive. | High | `dpkg-query -W -f='${Version}\n' nginx-core`, then compare against `1.18.0-0ubuntu1.7+esm5`. Also confirm ESM is active (`pro status`), because the fix only ships on the ESM pocket. | USN-9159-1 |

Note on the Ubuntu rows: the banner is identical across the vulnerable and patched builds and does not change with the fix, so banner matching alone classifies both as the same thing and is wrong half the time. Only the `dpkg` revision is authoritative. We bracketed the Jammy fix in the lab with `-6ubuntu14` (vulnerable) and `-6ubuntu14.24` (patched); USN-9159-1 names `-6ubuntu14.23` as the fixed revision, so any revision at or above `.23` is `not-affected`.

### Unknown rows (not verified by us; no advisory cited because unverified)

For every row below we did not reproduce the patch state, and we deliberately do not cite an advisory ID or a fixed version, because inventing one would be worse than admitting the gap. Resolve each on the host with the stated command. Treat the result as `unknown` until that command runs.

| Distro / product | Banner string(s) | Packaged version(s) | Epoch / revision that carries the fix | Actual patch state | Confidence | How to verify on-host | Source |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Debian (11 / 12 / 13 and derivatives) | `nginx/1.x.y` or bare `nginx`; Debian does not append an `(Ubuntu)`-style tag, and the distro backports under a frozen upstream version | unknown | unknown | `unknown` | Unknown | `dpkg-query -W -f='${Version}\n' nginx-core` (or `nginx-common`), then `nginx -V 2>&1`. Cross-check the installed version against the Debian security tracker for the running suite. | none cited (unverified) |
| RHEL / AlmaLinux / Rocky 9 (and RHEL 8) | often bare `nginx`, or `nginx/1.20.1` from the appstream module; backported under a frozen version with an rpm epoch | unknown | unknown (rpm epoch and release suffix, for example `N.elX`, resolve on-host) | `unknown` | Unknown | `rpm -q nginx` for the exact `epoch:version-release`, then `rpm -q --changelog nginx` piped to `head -n 40` to look for a backport entry, and `nginx -V 2>&1` for the build. | none cited (unverified) |
| Alpine Linux | `nginx/1.x.y` | unknown | unknown | `unknown` | Unknown | `apk info -v nginx` for the installed version, `apk policy nginx` for the repo revision, then `nginx -V 2>&1`. Compare against the Alpine `secdb` / aports for the running branch. | none cited (unverified) |
| Amazon Linux 2023 | `nginx/1.x.y` | unknown | unknown | `unknown` | Unknown | `rpm -q nginx`, then `dnf updateinfo info nginx` to see whether a security update is pending, and `nginx -V 2>&1`. | none cited (unverified) |
| Chainguard (Wolfi-based images) | `nginx/1.x.y` | unknown | unknown | `unknown` | Unknown | `apk info -v nginx` (Wolfi uses apk) or read the image SBOM / provenance attestation for the nginx package version, then `nginx -V 2>&1`. These images rebuild frequently, so pin by digest and read the SBOM for that digest. | none cited (unverified) |
| OpenResty | `openresty/1.x.y.z` (bundles its own nginx core) | unknown | unknown | `unknown` | Unknown | `openresty -V 2>&1` (equivalently `nginx -V 2>&1`) prints the embedded nginx core version. Map that core version against the upstream affected range, then confirm against OpenResty's own release notes for a backport. The visible `openresty/...` version is not the nginx core version. | none cited (unverified) |
| ingress-nginx (Kubernetes) | `nginx` (often version-stripped by the controller) | unknown | unknown | `unknown` | Unknown | `kubectl exec` into the controller pod and run `nginx -v` / `nginx -V 2>&1`, and separately read the controller image tag and its release notes. The controller version is not the nginx core version; resolve the embedded core. | none cited (unverified) |
| Kong (Gateway, OpenResty-based) | `kong/x.y.z` or an nginx banner depending on config | unknown | unknown | `unknown` | Unknown | `kong version --vv` or, inside the container, `nginx -V 2>&1` for the embedded OpenResty / nginx core. Classify on the core version, not the Kong release. | none cited (unverified) |
| Tengine | `Tengine` or `Tengine/x.y.z`, sometimes alongside an nginx base version | unknown | unknown | `unknown` | Unknown | `nginx -V 2>&1` prints the Tengine version and its nginx base version. Map the nginx base version against the affected range, then check Tengine's own advisories for a backport. | none cited (unverified) |
| NGINX Plus (F5) | `nginx/1.y.z` with the commercial package installed | unknown | unknown (F5 ships fixes as plus release `R-NN`) | `unknown` | Unknown | `nginx -v`, then `dpkg -l nginx-plus` (Debian/Ubuntu) or `rpm -q nginx-plus` (RHEL family) for the Plus package revision, and `nginx -V 2>&1`. Confirm the Plus release against F5's own security notification. | none cited (unverified) |

## How a scanner should set the verdict

1. If the host is in the verified table and the on-host command returns a version, apply the row's rule directly. `vulnerable`, `not-affected`, or, if the box is unreachable for the command, `unknown`.
2. If the host matches an unknown row, do not emit `vulnerable` or `not-affected` from the banner. Emit `candidate` only when the literal banner version falls in the affected range and the product is one that advertises its true upstream version (upstream mainline or stable, Tengine's nginx base, OpenResty's core after you resolve it). Otherwise emit `unknown`.
3. Never promote a backporting-distro banner (for example `nginx/1.18.0 (Ubuntu)`) past `unknown` on banner alone. Require the package revision.
4. Never emit `vulnerable` from the active h2c differential over TLS, and never fire the differential against a host you do not own. It discriminates only over cleartext h2c in the lab, and firing it is the corrupting operation.

## Source index

- Upstream fix and affected range: nginx security advisories (https://nginx.org/en/security_advisories.html); fix commit `e27f5fa84f`; fixed in 1.30.7 (stable) and 1.31.9 (mainline).
- Ubuntu backport: USN-9159-1; Jammy fixed at `1.18.0-6ubuntu14.23`, Focal fixed at `1.18.0-0ubuntu1.7+esm5` (ESM).
- Lab backport proof (this repository): `1.18.0-6ubuntu14` vulnerable, `1.18.0-6ubuntu14.24` patched, identical banner and HTTP/2 `SETTINGS`.
- Lab mainline differential (this repository): 1.31.8 vulnerable, 1.31.9 patched, cleartext h2c; no discrimination over TLS.
- All `unknown` rows: no source cited because we did not verify them. Resolve on-host.
