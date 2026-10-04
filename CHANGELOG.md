# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-04

### Added

- `status: {every, route, tz}`: a periodic table of all hosts (state, CPU, memory, swap, disk, open incidents, hosts not reporting) per environment.
- Telegram messages are sent as HTML; text between ``` lines is shown as a monospace block.

### Fixed

- The incident enrichment test no longer depends on the current date.

### Changed

- Release builds are Linux only (amd64, arm64).

## [0.1.1] - 2026-10-02

### Fixed

- `check-config` run by hand reads `secrets.env` next to the config (new flag `-env-file`), like the service does.

## [0.1.0] - 2026-10-02

### Added

- Fluent Bit ingest (JSON array or lines, gzip), one token per environment.
- SQLite storage with retention; heartbeat registry of hosts.
- Rules: threshold, text, lograte, anomaly, absent; `for`, severity, match, text templates.
- Incidents with open/resolve once, reminders (`repeat`), silences (API) and maintenance windows.
- Notifiers: Telegram (forum topics), Slack, e-mail (SMTP), webhook; routes with several destinations, digest and `send_resolved`.
- AI agents defined in YAML (OpenAI-compatible API): incident and daily-report triggers, prompt files, context limits, budget.
- URL probes with TLS certificate expiry; Lightsail burst capacity poller.
- Daily report with time zone.
- JSON API with OpenAPI, SSE, CORS, API keys and JWT (RS256, ES256, EdDSA); roles viewer, logs, admin.
- Config reload on SIGHUP; secrets from environment variables or `NAME_FILE`.
- `install.sh`: install, update (config checked first), checks-only, uninstall/purge; verifies release checksums.
- Example checks (system, PostgreSQL), Fluent Bit config, systemd units; container image and release binaries.

[0.2.0]: https://github.com/thomaskhub/loglantern/releases/tag/v0.2.0
[0.1.1]: https://github.com/thomaskhub/loglantern/releases/tag/v0.1.1
[0.1.0]: https://github.com/thomaskhub/loglantern/releases/tag/v0.1.0
