# Changelog

## Unreleased

- Added manually initiated TCP, HTTP, HTTPS, and TLS profiles pinned to registered, approved IP addresses and ports.
- Added bounded HTTP expectations, verified TLS metadata, health trends, persistent local alerts, and monitoring sections in PDF reports.
- Added service monitoring and alert interfaces with the original TCP scans and discovery available alongside them.

- Added asset groups, tags, notes, last-seen timestamps, and persisted availability history through additive SQLite migrations.
- Added bounded discovery progress, cancellation, and run history while retaining the synchronous discovery API.
- Recorded TCP duration and error categories and added an asset intelligence panel for recent observations and changes.

- Refined all six dashboard views, added inventory availability filters and history date filters, and preserved existing API routes.
- Added same-origin mutation checks, bounded JSON request bodies, redacted validation payloads, SQLite foreign-key enforcement, and additional CSV neutralization.
- Added browser and API regression coverage, release documentation, and CI.

## Earlier project phases

- Phase 4 added analytics, timeline events, and PDF reporting.
- Phase 3 added named service approvals, persistent scan jobs, comparisons, and JSON and CSV export.
- Phase 2 added scoped asset inventory and controlled discovery.
- Phase 1 established the local FastAPI, SQLite, and React application.
