# loglantern

Small, self-hosted monitoring for a handful of servers. Fluent Bit on every host ships logs, metrics
and check results to **one Go binary**, which:

- stores them in SQLite (pure Go, no CGO, one file),
- keeps a heartbeat registry of every host (up / missing / unknown),
- evaluates alert rules on a 2-hour in-memory window,
- opens and resolves incidents once, and sends them to Telegram (forum topics) or a webhook through a retrying outbox,
- optionally adds a short AI explanation (any OpenAI-compatible API, e.g. OpenRouter),
- probes URLs, and optionally reads Lightsail CPU burst capacity,
- sends a daily report,
- serves a read-only JSON API (OpenAPI, SSE, CORS) for dashboards, with API keys or JWTs.

It runs in about 40 MB RAM at 1,000 records/s, so a 512 MB VM is enough for several environments.

```
host: journald, checks, cpu, mem ──Fluent Bit──▶ :8440 ingest ─┬─▶ SQLite (batched writer)
                                                                ├─▶ heartbeat registry
                                                                └─▶ rules (2 h window) ─▶ incidents ─▶ outbox ─▶ Telegram / webhook
dashboard ◀── :8441 JSON API + SSE ◀── SQLite                                         └─▶ AI follow-up (optional)
```

## Quick start

```sh
go install github.com/thomkin/loglantern/cmd/loglantern@latest   # Go 1.26+
cp examples/config.yaml /etc/loglantern/config.yaml       # edit
echo 'LOGLANTERN_TOKEN_PROD=...' > /etc/loglantern/secrets.env
loglantern -config /etc/loglantern/config.yaml check-config
cp examples/systemd/loglantern.service /etc/systemd/system/ && systemctl enable --now loglantern
```

On each host, install Fluent Bit with [examples/fluent-bit/fluent-bit.conf](examples/fluent-bit/fluent-bit.conf)
and set `LOGLANTERN_TOKEN`, `LOGLANTERN_HOST`, `HOST_ROLE`, `LOGLANTERN_ADDR` in its environment.

Commands: `loglantern [-config file] [-log-level info] run | check-config | version`.

## Records

Fluent Bit `http` output with `format json`, `json_date_key date`, `json_date_format double` (gzip optional).
The ingest token (`Authorization: Bearer …`) decides the environment. Every record needs `host`;
`role` and `ip` are optional.

| kind | how | stored as |
|---|---|---|
| `log` (default) | journald fields `MESSAGE`, `PRIORITY`, `SYSLOG_IDENTIFIER`; or `message`/`level`/`service` | log line; JSON messages are parsed into fields |
| `metric` | `kind: metric`, `source: cpu`, numeric fields | series `cpu.cpu_p`, … (1-minute buckets) |
| `fact` | a JSON line from identifier `loglantern-fact`: `{"fact":"backup","status":"ok","age_h":3}` | series `backup.age_h` (number), `backup.status` (text) |

Checks are plain scripts that print a fact to journald (see [examples/check-disk.sh](examples/check-disk.sh)),
so they need no extra agent. Messages are cut at 8 KiB; ANSI colours are stripped; `ingest.mask_emails` hides e-mail addresses.

When loglantern is busy it answers `503`, and Fluent Bit keeps the data in its disk buffer and retries.

## Rules

| type | fires when | fields |
|---|---|---|
| `threshold` | newest value `op value` | `series`, `op` (`> >= < <= == !=`), `value` |
| `text` | newest text `==`/`!=` value | `series`, `op`, `value` |
| `lograte` | at least `count` matching lines in `per` | `level` (this or worse), `pattern` (regexp), `count`, `per` |
| `anomaly` | z-score of the newest value against the window ≥ `zscore` and change ≥ `min_delta` | `series`, `zscore`, `min_samples`, `min_delta` |

Common fields: `for` (condition must hold this long), `severity` (`info`, `warning`, `critical`),
`match` (`env`, `host`, `role`, `service`), and `text` (template with `{rule} {env} {host} {value} {detail} {series}`).
A series without new data for 10 minutes resolves its incidents; a host without data for `missing_after`
opens a `host-missing` incident. Each incident is announced once when it opens and once when it resolves. After a restart, the window is
rebuilt from the database and open incidents are not sent again.

## Routing and notifiers

Every route whose `match` fits (`env`, `host`, `role`, `service`, `severity` list) gets the message.
`telegram` sends to a chat; `target` picks a forum topic from `notifiers.telegram.topics`
(a Telegram group with topics enabled; the topic id is the `message_thread_id`). `webhook` posts
`{"text": "...", "target": "..."}`. Failed sends are retried with backoff (30 s up to 30 min), and Telegram's
`retry_after` is honoured. Messages stay in the outbox table until they are delivered.

## API

Base `/api/v1`, OpenAPI at `/api/v1/openapi.json`. All endpoints are `GET`.

| path | role |
|---|---|
| `health` | none |
| `me`, `hosts`, `incidents`, `series`, `series/names`, `counters`, `events` (SSE) | viewer |
| `logs` (cursor pagination) | logs |

Times accept RFC 3339, unix seconds or a duration back from now (`from=6h`). `env=a,b` narrows to
permitted environments. SSE (`events`) takes `?access_token=` because `EventSource` cannot send headers.
Origins in `cors` may call the API from a browser.

Auth: `auth.api_keys` (static keys, at least 16 characters, with role and environments) or `auth.jwt`
(RS256, ES256 or EdDSA public key; `exp` required; role from claim matches, e.g. `permissions.admin == true`
gives `logs`). Put the API behind a TLS reverse proxy.

## Optional parts

- **AI agents** (`ai:`): any OpenAI-compatible API (e.g. OpenRouter). Each agent in `ai.agents` sets
  when it runs (`on: incident_open` with an optional `match`, or `on: daily_report`), `model`,
  instructions (`prompt` inline or `prompt_file`), how much context it gets
  (`context: {logs, level, lookback, values}`) and an optional `route` for its answer. An agent makes
  one call without tools. Its answer is sent as a follow-up (`[AI <name>] …`) and stored on the incident;
  e-mails, tokens and passwords are masked first. All agents share a daily call budget, and alarms
  never depend on them. Without `agents`, a built-in `explain` agent runs on every new incident.
- **Probes** (`probes:`): series `probe.<name>.up`, `probe.<name>.ms` and text `probe.<name>.status`.
- **Lightsail** (`lightsail:`): active only when both credential variables are set. Every interval
  (default 15 min) it reads `BurstCapacityPercentage` and `BurstCapacityTime` into `lightsail.burst_pct`
  and `lightsail.burst_minutes`. IAM needs `lightsail:GetInstances` and `lightsail:GetInstanceMetricData`.
  These values never count as a heartbeat.
- **Daily report** (`report:`): hosts, incidents, error lines compared with the day before, and low burst capacity.

## Operations

- Retention (default): logs and metrics 5 days, hourly counters and incidents 90 days.
- One writer, with batches of up to 2,000 records every second; WAL mode; the API reads through a separate pool.
- Backup: `sqlite3 loglantern.db ".backup copy.db"` while running.
- Memory: run with `MemoryMax`/`GOMEMLIMIT` as in the systemd example.

## Development

```sh
go test -race ./...                                   # unit + integration (Fluent Bit e2e needs podman)
LOGLANTERN_LOAD=60s go test -run TestLoad -v ./test/  # 1,000 records/s against the real binary
```

## License

MIT
