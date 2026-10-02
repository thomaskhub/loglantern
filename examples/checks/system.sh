#!/bin/sh
# loglantern check: memory, swap, disks, load and failed systemd units as facts.
#   series: mem.used_pct mem.swap_pct disk.used_pct (/) disk_<mount>.used_pct
#           load.per_cpu systemd.failed systemd.failed_units (text)
# Usage: system.sh [extra mount ...]   e.g. system.sh /var/lib/postgresql
# Prints to stdout with LOGLANTERN_STDOUT=1, otherwise writes to journald (identifier loglantern-fact).
set -eu

emit() {
	if [ "${LOGLANTERN_STDOUT:-}" = 1 ]; then
		printf '%s\n' "$1"
	else
		printf '%s\n' "$1" | systemd-cat -t loglantern-fact
	fi
}

awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2}
	END {
		swap = (st > 0) ? (st - sf) * 100 / st : 0
		printf "{\"fact\":\"mem\",\"used_pct\":%.1f,\"swap_pct\":%.1f}\n", (t - a) * 100 / t, swap
	}' /proc/meminfo | while read -r line; do emit "$line"; done

disk() { # mount fact-name
	pct=$(df -P "$1" | awk 'NR == 2 { gsub("%", "", $5); print $5 }')
	ipct=$(df -Pi "$1" 2>/dev/null | awk 'NR == 2 { gsub("%", "", $5); print ($5 == "-" ? 0 : $5) }')
	emit "{\"fact\":\"$2\",\"mount\":\"$1\",\"used_pct\":${pct:-0},\"inodes_pct\":${ipct:-0}}"
}
disk / disk
for m in "$@"; do
	name=disk_$(printf '%s' "$m" | tr -c 'a-zA-Z0-9\n' '_' | sed 's/^_*//; s/_*$//')
	disk "$m" "$name"
done

cpus=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
awk -v c="$cpus" '{ printf "{\"fact\":\"load\",\"load1\":%s,\"per_cpu\":%.2f}\n", $1, $1 / c }' /proc/loadavg |
	while read -r line; do emit "$line"; done

if command -v systemctl >/dev/null 2>&1; then
	failed=$(systemctl list-units --state=failed --no-legend --plain 2>/dev/null | awk '{print $1}' | paste -sd, -)
	n=0
	[ -n "$failed" ] && n=$(printf '%s' "$failed" | tr ',' '\n' | wc -l)
	emit "{\"fact\":\"systemd\",\"failed\":$n,\"failed_units\":\"$failed\"}"
fi
