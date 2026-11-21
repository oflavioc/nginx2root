# Release checklist

- [x] Target repository is `Censys-Research/nginx2root`.
- [x] Verified `CVE-2026-123007` marker and post-dispatch stability note included.
- [x] Single genuine vulnerable 1.31.8 command-execution reproduction (2026-11-21, marker `/tmp/pwn-realrun-01`) included; no patched 1.31.9 control run was performed.
- [x] Upstream 36 component tests and profile validation passed.
- [x] Compact vulnerable/patched PCAP pair included; no large exploit captures.
- [x] PCAP privacy review completed: only private Docker IPs, ephemeral MACs, lab hostnames, stock nginx content, and the `POC-SYNC` PING. No personal names, email addresses, credentials, cookies, private keys, public IPs, or user file paths found.
- [x] Unlicensed Rapid7 source removed from the public tree; upstream remains linked in `third_party/README.md`.
- [x] Other four CVEs are not advertised as working RCE PoCs.
- [x] Unified suite defaults to listing; archived evidence never reports fresh RCE verification.
- [x] Censys-authored code and evidence carry Apache-2.0 terms; third-party components retain their own terms.
- [x] No private keys, credentials, lab certificates, crash dumps, or large source trees staged.
- [ ] Fresh-clone smoke test of the final public tree.
- [ ] Maintainer approval before changing repository visibility to public.

## Code inventory

| File | Purpose |
| --- | --- |
| `suite/__init__.py` | Package marker and public entry-point export. |
| `suite/__main__.py` | Allows `python -m suite` to invoke the CLI. |
| `suite/cli.py` | Click/Rich commands for listing, building, running, and verifying adapters; defaults to safe listing. |
| `suite/models.py` | Pydantic manifest, budget, evidence, and verification models; target/path validation and marker parsing. |
| `suite/adapters.py` | Loads manifests, executes bounded stages, and validates archived or fresh marker/control evidence. |
| `suite/runner.py` | Runs shell-free subprocesses with process-group termination, timeouts, and output limits. |
| `suite/manifests/cve-2026-123007.json` | Archived single-run Rapid7 RCE evidence; patched-control metadata records that no patched run was performed; never reruns the baseline. |
| `suite/tests/test_suite.py` | Mocked unit tests for guards, parsing, budgets, archived evidence, and RCE verification. |
| `pyproject.toml` | Python dependencies and pytest configuration. |
| `uv.lock` | Reproducible Python dependency lockfile. |

The public tree does not include the upstream exploit Python files or native C streamer. Those remain in Rapid7's linked repository.
