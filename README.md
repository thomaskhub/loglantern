# loglantern

[![ci](https://github.com/thomaskhub/loglantern/actions/workflows/ci.yml/badge.svg)](https://github.com/thomaskhub/loglantern/actions/workflows/ci.yml)

Small, self-hosted monitoring for a handful of servers. Fluent Bit on every host ships logs, metrics
and check results to **one Go binary**, which:

- stores them in SQLite (pure Go, no CGO, one file),
- keeps a heartbeat registry of every host (up / missing / unknown),
- evaluates alert rules on a 2-hour in-memory window,
- opens and resolves incidents once each, with reminders, silences and maintenance windows,
- sends them to Telegram (forum topics), Slack, e-mail or a webhook through a retrying outbox,
- optionally adds short AI explanations from agents you define in YAML (any OpenAI-compatible API),
- probes URLs (including TLS certificate expiry), and optionally reads Lightsail CPU burst capacity,
- sends a daily report,
- serves a JSON API (OpenAPI, SSE, CORS) for dashboards, with API keys or JWTs.

It runs in about 40 MB RAM at 1,000 records/s, so a 512 MB VM is enough for several environments.

```
host: journald, checks, cpu, mem ──Fluent Bit──▶ :8440 ingest ─┬─▶ SQLite (batched writer)
                                                                ├─▶ heartbeat registry
                                                                └─▶ rules (2 h window) ─▶ incidents ─▶ outbox ─▶ Telegram / Slack / e-mail / webhook
dashboard ◀── :8441 JSON API + SSE ◀── SQLite                                         └─▶ AI agents (optional)
```

**Scope:** one instance for up to a few dozen hosts. There is no clustering or high availability; if
loglantern is down, Fluent Bit buffers on disk and replays when it is back. For hundreds of hosts or
long retention, use Prometheus/Loki/VictoriaMetrics.

## Install

**Recommended: the install script** (Linux with systemd, amd64 or arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/thomaskhub/loglantern/main/install.sh | sudo sh
```

The script:
- downloads the latest release and verifies its checksum;
- creates the user `loglantern`, plus `/etc/loglantern` and `/var/lib/loglantern`;
- installs `/usr/local/bin/loglantern` and the systemd unit;
- writes a starter config, plus a `secrets.env` with a generated ingest token (printed at the end);
- starts the service.

It also copies the full example to `/etc/loglantern/config.example.yaml`.

Run it again to update. It keeps your config and secrets, checks the config with the new binary first,
and restarts only if the check passes.

| option | |
|---|---|
| `--version v0.2.0` | a specific release instead of the latest |
| `--archive FILE` | install from a downloaded release archive (offline, Ansible) |
| `--env NAME` | environment of the starter config (default `prod`) |
| `--checks` / `--checks-only` | also / only install the check scripts and their timer (for monitored hosts) |
| `--uninstall` / `--purge` | remove the program, keeping / deleting config, data and user |

Pass options with `| sudo sh -s -- --checks-only`. The script is also attached to every release.

Other ways:
- **Binary:** download from [Releases](https://github.com/thomaskhub/loglantern/releases), then use `examples/systemd/loglantern.service`.
- **Container:** `ghcr.io/thomaskhub/loglantern:latest` (distroless, runs as non-root; mount the config at
  `/etc/loglantern/config.yaml` and a writable volume at `/var/lib/loglantern`; listen on `0.0.0.0`).
  Docker adds a daemon, so on small VMs the binary is lighter.
- **From source:** `go install github.com/thomaskhub/loglantern/cmd/loglantern@latest` (Go 1.26+), or `docker build .`.

Commands: `loglantern [-config file] [-log-level info] run | check-config | version`.
`systemctl reload loglantern` (SIGHUP) applies a changed config without dropping data; a broken config
is rejected and the running one stays. Changing `listen` or `storage.path` needs a restart.

### On every host

1. Install Fluent Bit and use [examples/fluent-bit/fluent-bit.conf](examples/fluent-bit/fluent-bit.conf).
   Set `LOGLANTERN_TOKEN`, `LOGLANTERN_HOST`, `HOST_ROLE` and `LOGLANTERN_ADDR` in its environment.
2. Optional checks: `curl -fsSL https://raw.githubusercontent.com/thomaskhub/loglantern/main/install.sh | sudo sh -s -- --checks-only`
   installs [examples/checks](examples/checks) to `/usr/local/lib/loglantern-checks/` with a timer that runs them every 2 minutes. Included:
   - `system.sh`: `mem.used_pct`, `mem.swap_pct`, `disk.used_pct`, `disk.inodes_pct` (extra mounts as `disk_<mount>.*`), `load.per_cpu`, `systemd.failed`
   - `postgres.sh` (runs as the postgres user; does nothing on hosts without PostgreSQL): `postgres.up`, `postgres.primary`, `postgres.connections_pct`, `replication.lag_s`, `replication.streaming`, `backup.status`, `backup.age_h` (pgBackRest)

For Docker hosts, add Fluent Bit's `docker` or `forward` input; any record with `host` works.

## Records

Fluent Bit `http` output with `format json`, `json_date_key date`, `json_date_format double` (gzip optional).
The ingest token (`Authorization: Bearer …`) decides the environment. Every record needs `host`;
`role` and `ip` are optional.

| kind | how | stored as |
|---|---|---|
| `log` (default) | journald fields `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`, or `message`/`level`/`service` | log line; JSON messages are parsed into fields |
| `metric` | `kind: metric`, `source: cpu`, numeric fields | series `cpu.cpu_p`, … (1-minute buckets) |
| `fact` | a JSON line from the identifier `loglantern-fact`: `{"fact":"backup","status":"ok","age_h":3}` | series `backup.age_h` (number), `backup.status` (text) |

A check is any script that prints a fact to journald (`systemd-cat -t loglantern-fact`), so checks need no extra agent.
Messages are cut at 8 KiB and ANSI colours are stripped; `ingest.mask_emails` hides e-mail addresses.
When loglantern is busy it answers `503`, and Fluent Bit keeps the data and retries.

## Rules

| type | fires when | fields |
|---|---|---|
| `threshold` | the newest value `op value` | `series`, `op` (`> >= < <= == !=`), `value` |
| `text` | the newest text `==`/`!=` value | `series`, `op`, `value` |
| `lograte` | at least `count` matching lines within `per` | `level` (this or worse), `pattern` (regexp), `count`, `per` |
| `anomaly` | the z-score of the newest value against the window is ≥ `zscore`, and it changed by ≥ `min_delta` | `series`, `zscore`, `min_samples`, `min_delta` |
| `absent` | a series that was reported before has no value for `max_age` (e.g. a dead check or backup job) | `series`, `max_age` |

Common fields:
- `for`: how long the condition must hold.
- `severity`: `info`, `warning` or `critical`.
- `match`: limits the rule by `env`, `host`, `role` or `service`.
- `text`: a template using `{rule} {env} {host} {value} {detail} {series}`.

Hosts and data:
- A host that sends no data for `missing_after` opens a `host-missing` incident.
- Probe and Lightsail data never count as a heartbeat.
- A series without new data for 10 minutes resolves its threshold, text and anomaly incidents. Use `absent` to alert on that instead.

Incidents:
- Each incident is announced once when it opens and once when it resolves.
- After a restart, the window is rebuilt from the database and open incidents are not sent again.

## Notifiers and routes

`notifiers` are named outputs; each has exactly one type section:

| type | sends with | targets |
|---|---|---|
| `telegram` | Bot API, plain text | `topics`: name → forum topic id (`message_thread_id`) |
| `slack` | bot token (`chat.postMessage`) or incoming webhook | `channels`: name → channel id (bot token only) |
| `email` | SMTP: STARTTLS (587, default), implicit TLS (465), or `none` for a local relay | `targets`: name → recipients; `to` is the default |
| `webhook` | POST `{"text", "target"}` | any string, passed on |

`routes` decide where messages go. Every route whose `match` fits (`env`, `host`, `role`, `service`,
`severity` list) sends to each entry of `send` (`notifier` or `notifier/target`). Per-route options:

- `digest: 1h`: bundle messages into at most one delivery per period (good for e-mail).
- `repeat: 4h`: remind about incidents that are still open.
- `send_resolved: false`: skip the resolved message.

AI agents and the daily report name a route too.

Each destination has its own outbox row, so a failing destination is retried with backoff (30 s up to
30 min) without blocking the others. `retry_after`/`Retry-After` is honoured, and order is kept per destination.

## Silences and maintenance

A silence mutes notifications; incidents are still recorded and visible in the API.
- If an incident is still open when its silence ends, it is announced then, marked "open since …".
- A resolved message only goes where the opening was announced.

- **Maintenance windows** in the config: weekly (`days`, `from`, `to`, `tz`; may cross midnight) or
  one-off (`starts`, `ends`), with an optional `match` and `rule`.
- **Ad-hoc silences** through the API (role `admin`):
  ```sh
  curl -H "Authorization: Bearer $KEY" -d '{"env":"prod","host":"db-1","duration":"2h","comment":"upgrade"}' \
       https://ops.example.org/api/v1/silences
  curl -H "Authorization: Bearer $KEY" -X DELETE https://ops.example.org/api/v1/silences/7
  ```

## AI agents (optional)

Any OpenAI-compatible API works, e.g. OpenRouter or a local Ollama. Each entry in `ai.agents` sets:
- when it runs: `on: incident_open` with an optional `match`, or `on: daily_report`;
- `model`;
- instructions: `prompt` inline or `prompt_file`;
- how much context it gets: `context: {logs, level, lookback, values}`;
- an optional `route` for its answer.

How agents behave:
- An agent makes one call and has no tools.
- Its answer is sent as a follow-up (`[AI <name>] …`) and stored on the incident.
- E-mails, tokens and passwords are masked before anything is sent.
- All agents share a daily call budget, and alarms never depend on them.
- Without `agents`, a built-in `explain` agent runs on every new incident.

## Probes and Lightsail

- **Probes** (`probes:`) give the series `probe.<name>.up`, `probe.<name>.ms`, `probe.<name>.cert_days`
  (HTTPS) and the text `probe.<name>.status`.
- **Lightsail** (`lightsail:`) is active only when both credential variables are set.
  - Every interval (default 15 min) it reads `BurstCapacityPercentage` and `BurstCapacityTime` into
    `lightsail.burst_pct` and `lightsail.burst_minutes`.
  - The IAM user needs `lightsail:GetInstances` and `lightsail:GetInstanceMetricData`.
- **Daily report** (`report: {at, tz, route}`): hosts, incidents, error lines compared with the day before, and low burst capacity.

## API

Base `/api/v1`, OpenAPI at `/api/v1/openapi.json`.

| path | role |
|---|---|
| `GET health` | none |
| `GET me`, `hosts`, `incidents`, `series`, `series/names`, `counters`, `silences`, `events` (SSE) | viewer |
| `GET logs` (cursor pagination) | logs |
| `POST silences`, `DELETE silences/{id}` | admin |

- Times accept RFC 3339, unix seconds, or a duration back from now (`from=6h`).
- `env=a,b` narrows the result to permitted environments.
- SSE (`events`) takes `?access_token=`, because `EventSource` cannot send headers.
- Origins listed in `cors` may call the API from a browser.

Auth comes in two forms:
- `auth.api_keys`: static keys of at least 16 characters, each with a role and environments.
- `auth.jwt`: an RS256, ES256 or EdDSA public key; `exp` is required. The role comes from claim matches; the highest matching role wins.

Put the API behind a TLS reverse proxy.

## Configuration

See [examples/config.yaml](examples/config.yaml) for every option.
- Secrets never go into the file: each `*_env` names an environment variable, and `NAME_FILE=/path` reads the value from a file (Docker/Kubernetes secrets).
- Unknown keys are errors, so typos are caught by `check-config`.

## Operations

- Retention (default): logs and metrics 5 days, hourly counters and incidents 90 days.
- One writer, with batches of up to 2,000 records every second; WAL mode; the API reads through a separate pool.
- Backup: `sqlite3 loglantern.db ".backup copy.db"` while running.
- Memory: run with `MemoryMax`/`GOMEMLIMIT` as in the systemd example.
- `GET /api/v1/health` shows the outbox backlog, the ingest counters and the last write.

## Development

```sh
go test -race ./...                                   # unit + integration (the Fluent Bit e2e needs podman)
LOGLANTERN_LOAD=60s go test -run TestLoad -v ./test/  # 1,000 records/s against the real binary
LOGLANTERN_INSTALL_TEST=1 go test -run TestInstallScript -v ./test/  # install.sh in a systemd container (podman)
```

A new notifier type is a new section in `config.Notifier` plus a `Send(ctx, target, text)`
implementation in `internal/notify`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
