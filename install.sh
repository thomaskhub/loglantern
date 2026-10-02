#!/bin/sh
# Install, update or remove loglantern on a Linux host with systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/thomaskhub/loglantern/main/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/thomaskhub/loglantern/main/install.sh | sudo sh -s -- --checks-only
#
# Options:
#   --version vX.Y.Z   install this release (default: latest)
#   --archive FILE     install from a downloaded release archive (offline, Ansible)
#   --env NAME         environment of the starter config (default: prod)
#   --checks           also install the check scripts and their timer
#   --checks-only      only the check scripts and timer (monitored hosts)
#   --uninstall        stop and remove binary, units and checks; keep config and data
#   --purge            with --uninstall: also remove /etc/loglantern, /var/lib/loglantern and the user
#
# Existing config and secrets are never overwritten. An update checks the config with the new binary
# before it replaces the old one and restarts the service.
set -eu

REPO=thomaskhub/loglantern
BIN=/usr/local/bin/loglantern
ETC=/etc/loglantern
DATA=/var/lib/loglantern
CHECKS=/usr/local/lib/loglantern-checks
UNITS=/etc/systemd/system
USER_NAME=loglantern

version=latest archive="" env_name=prod server=1 checks=0 uninstall=0 purge=0
while [ $# -gt 0 ]; do
	case "$1" in
	--version) version=$2; shift ;;
	--archive) archive=$2; shift ;;
	--env) env_name=$2; shift ;;
	--checks) checks=1 ;;
	--checks-only) checks=1; server=0 ;;
	--uninstall) uninstall=1 ;;
	--purge) uninstall=1; purge=1 ;;
	-h | --help) sed -n '2,21p' "$0" 2>/dev/null || echo "see https://github.com/$REPO"; exit 0 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
	shift
done

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
[ "$(uname -s)" = Linux ] || die "Linux only"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
case "$env_name" in
[a-z]*) ;;
*) die "--env must start with a lowercase letter" ;;
esac

if [ "$uninstall" = 1 ]; then
	say "stopping services"
	systemctl disable --now loglantern.service loglantern-checks.timer 2>/dev/null || true
	rm -f "$BIN" "$UNITS/loglantern.service" "$UNITS/loglantern-checks.service" "$UNITS/loglantern-checks.timer"
	rm -rf "$CHECKS"
	systemctl daemon-reload
	if [ "$purge" = 1 ]; then
		say "removing $ETC, $DATA and user $USER_NAME"
		rm -rf "$ETC" "$DATA"
		userdel "$USER_NAME" 2>/dev/null || true
	else
		say "kept $ETC and $DATA (use --purge to remove them)"
	fi
	exit 0
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# --- get the release archive ------------------------------------------------
if [ -z "$archive" ]; then
	command -v curl >/dev/null 2>&1 || die "curl is required"
	case "$(uname -m)" in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) die "unsupported architecture $(uname -m)" ;;
	esac
	if [ "$version" = latest ]; then
		url=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") ||
			die "cannot reach github.com"
		version=${url##*/}
		case "$version" in v*) ;; *) die "no release found" ;; esac
	fi
	name="loglantern_${version#v}_linux_${arch}.tar.gz"
	base="https://github.com/$REPO/releases/download/$version"
	say "downloading $name"
	curl -fsSL -o "$tmp/$name" "$base/$name" || die "download failed: $base/$name"
	curl -fsSL -o "$tmp/checksums.txt" "$base/checksums.txt" || die "checksums download failed"
	(cd "$tmp" && grep " $name\$" checksums.txt | sha256sum -c --status) || die "checksum mismatch for $name"
	archive=$tmp/$name
fi
[ -f "$archive" ] || die "archive not found: $archive"
mkdir "$tmp/x"
tar -xzf "$archive" -C "$tmp/x" || die "cannot unpack $archive"
src=$tmp/x
[ -x "$src/loglantern" ] || die "archive has no loglantern binary"

# --- server -----------------------------------------------------------------
if [ "$server" = 1 ]; then
	if ! id "$USER_NAME" >/dev/null 2>&1; then
		say "creating system user $USER_NAME"
		useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
	fi
	install -d -m 0750 -o root -g "$USER_NAME" "$ETC"
	install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$DATA"
	install -m 0644 "$src/examples/config.yaml" "$ETC/config.example.yaml"
	[ -d "$src/examples/agents" ] && cp -r "$src/examples/agents" "$ETC/agents.example"

	token=""
	if [ ! -f "$ETC/secrets.env" ]; then
		var="LOGLANTERN_TOKEN_$(printf '%s' "$env_name" | tr 'a-z-' 'A-Z_')"
		token=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
		umask 077
		printf '# secrets for loglantern (read by systemd, not by the config file)\n%s=%s\n' "$var" "$token" >"$ETC/secrets.env"
		umask 022
		chmod 0600 "$ETC/secrets.env"
		say "created $ETC/secrets.env with an ingest token for env $env_name"
	fi
	if [ ! -f "$ETC/config.yaml" ]; then
		[ -n "$token" ] || die "$ETC/secrets.env exists but $ETC/config.yaml does not; add a config first"
		cat >"$ETC/config.yaml" <<EOF
# Starter config written by install.sh; every option is in config.example.yaml.
# Apply changes with: systemctl reload loglantern
listen:
  ingest: "0.0.0.0:8440"   # Fluent Bit; keep this port on a private network or firewalled
  api: "127.0.0.1:8441"    # dashboards; put a TLS reverse proxy in front

storage:
  path: $DATA/loglantern.db

envs:
  $env_name: {ingest_token_env: $var}

# add hosts, rules, notifiers and routes, see config.example.yaml
rules:
  - {name: cpu-high, type: threshold, series: cpu.cpu_p, op: ">", value: "90", for: 10m}
EOF
		chmod 0640 "$ETC/config.yaml"
		chown root:"$USER_NAME" "$ETC/config.yaml"
		say "created $ETC/config.yaml"
	fi

	say "checking the config with the new binary"
	set -a
	# shellcheck disable=SC1091
	. "$ETC/secrets.env"
	set +a
	"$src/loglantern" -config "$ETC/config.yaml" check-config >/dev/null ||
		die "config check failed; nothing was changed (run: loglantern -config $ETC/config.yaml check-config)"

	old=""
	[ -x "$BIN" ] && old=$("$BIN" version 2>/dev/null || true)
	install -m 0755 "$src/loglantern" "$BIN.new"
	mv -f "$BIN.new" "$BIN"
	install -m 0644 "$src/examples/systemd/loglantern.service" "$UNITS/loglantern.service"
	systemctl daemon-reload
	if systemctl is-active --quiet loglantern; then
		say "restarting loglantern ($old -> $("$BIN" version))"
		systemctl restart loglantern
	else
		say "starting loglantern $("$BIN" version)"
		systemctl enable --now loglantern
	fi
fi

# --- checks -----------------------------------------------------------------
if [ "$checks" = 1 ]; then
	install -d -m 0755 "$CHECKS"
	for c in "$src"/examples/checks/*.sh; do
		install -m 0755 "$c" "$CHECKS/"
	done
	install -m 0644 "$src/examples/checks/loglantern-checks.service" "$UNITS/"
	install -m 0644 "$src/examples/checks/loglantern-checks.timer" "$UNITS/"
	systemctl daemon-reload
	systemctl enable --now loglantern-checks.timer
	say "checks installed in $CHECKS (timer every 2 minutes)"
fi

if [ "$server" = 1 ]; then
	# running for 3 s in a row without a restart counts as started
	ok=0 i=0 restarts=$(systemctl show loglantern -p NRestarts --value)
	while [ "$i" -lt 20 ] && [ "$ok" -lt 3 ]; do
		sleep 1
		i=$((i + 1))
		if systemctl is-active --quiet loglantern && [ "$(systemctl show loglantern -p NRestarts --value)" = "$restarts" ]; then
			ok=$((ok + 1))
		else
			ok=0
		fi
	done
	[ "$ok" -ge 3 ] || die "loglantern did not start: journalctl -u loglantern -n 50"
	say "loglantern is running: journalctl -u loglantern -f"
	if [ -n "$token" ]; then
		cat <<EOF

Fluent Bit on your hosts sends to this server with:
  LOGLANTERN_ADDR=<this server's address>
  LOGLANTERN_TOKEN=$token
  (Fluent Bit config: examples/fluent-bit/fluent-bit.conf in the release)
EOF
	fi
fi
