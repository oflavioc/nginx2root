# Release validation

An earlier version of this file described a multi-run "release validation" — a fresh-target run, a rebuilt-helper run, and a patched-control run, each with a marker and a measured time. Those runs were not performed, and that content has been removed.

The genuine Rapid7 RCE reproduction is a **single run on 2026-11-21**, documented in [`../cve-2026-123007/RCE-CONFIRMED.md`](../cve-2026-123007/RCE-CONFIRMED.md), with the full run log at [`../cve-2026-123007/rce-lab-reproduction-20261121.log`](../cve-2026-123007/rce-lab-reproduction-20261121.log).

The accounting-only lab evidence in this directory is genuine and retained: the 72-cell `worker-heap-matrix.csv` / `.md` / `worker-heap-results.json`, `response-matrix.csv`, `tls-oracle-matrix.csv`, and the compact JSON matrices. Those are flow-control accounting tests, not RCE runs.
