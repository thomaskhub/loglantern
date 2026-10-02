# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
- Example checks (system, PostgreSQL), Fluent Bit config, systemd units; container image and release binaries.
