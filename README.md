# loglantern

Small, self-hosted monitoring for a handful of servers: Fluent Bit on every host ships logs,
metrics and check results to one Go binary, which stores them in SQLite, decides alarms by rules,
sends them (Telegram, webhook) and offers a JSON API for dashboards.

Status: under construction.

## License

MIT
