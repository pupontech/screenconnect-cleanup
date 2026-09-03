# ScreenConnect report relay

This directory contains the receive-only relay used by `Submit-ConnectWiseReport.ps1`.
It is a private holding service, not a ConnectWise submission client.

- `app.py` accepts authenticated ZIP uploads at `POST /v1/uploads`.
- `export_reports.py` is a root-only local bulk exporter.
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
