#!/bin/sh
# loglantern check: PostgreSQL role, replication lag and pgBackRest backups as facts. Run as postgres.
#   series: postgres.up postgres.primary postgres.connections_pct
#           replication.lag_s replication.streaming (standby)
#           backup.status (text: ok | error | none) backup.age_h (primary, when pgbackrest is installed)
# Env: PGHOST/PGPORT as usual; PGBACKREST_STANZA (default main).
set -u

emit() {
	if [ "${LOGLANTERN_STDOUT:-}" = 1 ]; then
		printf '%s\n' "$1"
	else
		printf '%s\n' "$1" | systemd-cat -t loglantern-fact
	fi
}
q() { psql -XAtq -v ON_ERROR_STOP=1 -c "$1" 2>/dev/null; }

if ! q 'SELECT 1' >/dev/null; then
	emit '{"fact":"postgres","up":0}'
	exit 0
fi
standby=$(q 'SELECT pg_is_in_recovery()')
conns=$(q "SELECT round(100.0 * count(*) / current_setting('max_connections')::int, 1) FROM pg_stat_activity")
primary=1
[ "$standby" = t ] && primary=0
emit "{\"fact\":\"postgres\",\"up\":1,\"primary\":$primary,\"connections_pct\":$conns}"

if [ "$standby" = t ]; then
	# an idle primary sends no WAL: lag counts only when not streaming or WAL is waiting to be replayed
	row=$(q "SELECT CASE WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn() THEN 0
		ELSE COALESCE(EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp()), 0)::int END,
		(SELECT count(*) FROM pg_stat_wal_receiver WHERE status = 'streaming')")
	lag=${row%%|*}
	streaming=${row##*|}
	emit "{\"fact\":\"replication\",\"lag_s\":${lag:-0},\"streaming\":${streaming:-0}}"
	exit 0
fi

if command -v pgbackrest >/dev/null 2>&1; then
	info=$(pgbackrest --stanza="${PGBACKREST_STANZA:-main}" --output=json info 2>/dev/null)
	if [ -z "$info" ]; then
		emit '{"fact":"backup","status":"error","age_h":-1}'
		exit 0
	fi
	printf '%s' "$info" | python3 -c '
import json, sys, time
s = json.load(sys.stdin)[0]
bk = s.get("backup") or []
st = "ok" if s.get("status", {}).get("code") == 0 else "error"
if not bk:
    print(json.dumps({"fact": "backup", "status": "none", "age_h": -1}))
else:
    age = (time.time() - bk[-1]["timestamp"]["stop"]) / 3600
    print(json.dumps({"fact": "backup", "status": st, "age_h": round(age, 1)}))
' | while read -r line; do emit "$line"; done
fi
