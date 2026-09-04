# ScreenConnect report relay

This directory contains the receive-only relay used by `Submit-ConnectWiseReport.ps1`.
It is a private holding service, not a ConnectWise submission client.

- `app.py` accepts authenticated ZIP uploads at `POST /v1/uploads`.
- `export_reports.py` is a root-only local bulk exporter that bundles every
  stored receipt into one private archive.
- `export_iocs.py` is a root-only mass relay/server IOC exporter. It decrypts
  each stored receipt, reads only `connectwise-report.json`, and writes
  deduplicated observed relay outputs: `relay-addresses.txt`,
  `screenconnect-relays.csv`, `connectwise-abuse-summary.txt`, and
  `screenconnect-relays.json`. Raw evidence and binaries are never extracted
  and never copied into the outputs; observed data stays separate from any
  external IOC list supplied with `--external-ioc-list`.
- `screenconnect-report-relay-ioc-export` is the wrapper that runs
  `export_iocs.py` from the deployed `/opt/screenconnect-report-relay`.
- `cleanup_expired.py` is run daily by the systemd timer.
- `screenconnect-report-relay.service` is the systemd sandbox.
- `relay.env.example` documents the non-secret configuration shape.

The live service stores uploads under `/var/lib/screenconnect-report-relay/inbox`,
encrypts them with an age recipient, and exposes only `/healthz` and the upload
route through the reverse proxy. The bearer-token digest and age recipient in
the live environment file are generated during deployment and are never kept in
this repository.

The client package is intentionally sanitized. Raw config files, raw evidence,
parameter blobs, credentials, and private keys are not sent automatically.
ConnectWise submission remains a reviewed action through its official Trust
Center workflow.
