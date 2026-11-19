#!/usr/bin/env bash
# Sentinela installer - https://github.com/Noz-AF-Angola/sentinela
#
#   curl -fsSL https://sentinela.nozaf.ao/instalar.sh | sudo bash
#
# or, to read it first (recommended):
#
#   curl -fsSLO https://github.com/Noz-AF-Angola/sentinela/releases/latest/download/instalar.sh
#   less instalar.sh && sudo bash instalar.sh
#
# Commands (Portuguese names work too):
#   install   | instalar     install or repair; safe to run again (default)
#   update    | actualizar   install the latest release, keep configuration and accounts
#   uninstall | desinstalar  remove the service; accounts stay in /etc/sentinela unless SENTINELA_PURGE=1
#   user NAME [admin|viewer] | utilizador ...   create an account or reset its password and TOTP
#   status    | estado       show what is installed (read-only)
#
# After the first install the same script is kept as /usr/local/sbin/sentinela-admin,
# so later you run: sudo sentinela-admin update | user NAME | status | uninstall
#
# Environment variables:
#   SENTINELA_VERSION=x.y.z   release to install (default: the latest)
#   SENTINELA_LISTEN=ADDR:PORT  address of the web interface (default 127.0.0.1:8095;
#                             a public address is refused unless SENTINELA_ALLOW_PUBLIC=1)
#   SENTINELA_YES=1           answer yes to installing missing dependencies (never to telemetry)
#   SENTINELA_TELEMETRIA=0    never send the anonymous install count, and do not ask
#   SENTINELA_PURGE=1         with uninstall, also delete /etc/sentinela (accounts, LAPI password)
#   SENTINELA_FROM=DIR        install from a local folder holding the release files (offline)
#
# What it checks before installing anything: every downloaded file must match SHA256SUMS,
# and SHA256SUMS must carry a valid OpenPGP signature from the release key below
# (fingerprint 5493 6EE1 C783 51E9 FE49  29A0 2206 DA32 8A60 8A83).
#
# Telemetry: at the end of an interactive install you are asked [y/N] whether to send one
# anonymous message (random id, version, OS, architecture, event). Nothing is sent if you
# answer no, if SENTINELA_TELEMETRIA=0, or if there is no terminal. Details: README, "Telemetry".
#
# MIT licence. Author: Gelson Fernandes.

set -euo pipefail

REPO=Noz-AF-Angola/sentinela
FPR=54936EE1C78351E9FE4929A02206DA328A608A83
TELEMETRY_URL=${SENTINELA_TELEMETRIA_URL:-https://apoio.nozaf.ao/v1/instalacoes}
SUPPORT_URL="https://apoio.nozaf.ao/?projecto=sentinela"
BIN=/usr/local/bin/sentinela
ADMIN=/usr/local/sbin/sentinela-admin
ETC=/etc/sentinela
ENVF=$ETC/sentinela.env
USERS=$ETC/users.txt
UNIT=/etc/systemd/system/sentinela.service
SUDOERS=/etc/sudoers.d/sentinela
DEFAULT_LISTEN=127.0.0.1:8095

read -r -d '' RELEASE_KEY <<'KEY' || true
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEav1nGxYJKwYBBAHaRw8BAQdAKz60vnY+oD/GzLZzK3Z4A0pGOOuN8QxEG3mp
Hk7Klue0JUdlbHNvbiBGZXJuYW5kZXMgPG5vei5hZkBob3RtYWlsLmNvbT6ItQQT
FgoAXRYhBFSTbuHHg1Hp/kkpoCIG2jKKYIqDBQJq/WcbGxSAAAAAAAQADm1hbnUy
LDIuNSsxLjEyLDAsMwIbAwUJA8JnAAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIX
gAAKCRAiBtoyimCKg9bEAQDXS/kQBQ4AxswEIqRaq6n1Paln1vBDeiyVdAzEIQ+y
yQD/a1Bo68hwdFlBRs0GYwh1gEV/Eau0qGYaP5yjyAWinQc=
=/DfR
-----END PGP PUBLIC KEY BLOCK-----
KEY

# ---------------------------------------------------------------- helpers

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'; else B='' G='' Y='' R='' N=''; fi
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '    %s!%s %s\n' "$Y" "$N" "$*" >&2; }
die()  { printf '\n%sStopped:%s %s\n' "$R" "$N" "$*" >&2; exit 1; }

TMP=
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT

# A terminal we can talk to, even when the script itself arrives on stdin (curl | bash).
has_tty() { [ -r /dev/tty ] && [ -w /dev/tty ] && { : </dev/tty; } 2>/dev/null; }

# ask "question" default(y|n) -> 0 for yes. Without a terminal it returns the default.
ask() {
	local q=$1 def=${2:-n} a hint='[y/N]'
	[ "$def" = y ] && hint='[Y/n]'
	has_tty || { [ "$def" = y ]; return; }
	printf '    %s %s ' "$q" "$hint" >/dev/tty
	IFS= read -r a </dev/tty || a=
	case "${a,,}" in
		y|yes|s|sim) return 0 ;;
		n|no|nao|não) return 1 ;;
		*) [ "$def" = y ] ;;
	esac
}

# Installing something the user did not ask for always needs a yes (or SENTINELA_YES=1).
confirm_install() {
	[ "${SENTINELA_YES:-0}" = 1 ] && return 0
	has_tty || die "$1 is missing. Run again in a terminal to confirm, or set SENTINELA_YES=1."
	ask "$1 is missing. Install it now?" n
}

pkg_install() {  # pkg_install name...
	if command -v apt-get >/dev/null; then
		DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
	elif command -v dnf >/dev/null; then dnf install -y -q "$@"
	elif command -v yum >/dev/null; then yum install -y -q "$@"
	elif command -v zypper >/dev/null; then zypper --non-interactive install "$@"
	else die "no supported package manager found; install $* by hand"
	fi
}

need_cmd() {  # need_cmd command package
	command -v "$1" >/dev/null && return 0
	confirm_install "$2" || die "$2 is required"
	pkg_install "$2"
	command -v "$1" >/dev/null || die "$2 did not install $1"
}

envget() {  # value of KEY in the env file
	[ -f "$ENVF" ] || return 0
	sed -n "s/^$1=//p" "$ENVF" | tail -1
}

# ---------------------------------------------------------------- platform

check_platform() {
	[ "$(id -u)" = 0 ] || die "run as root: curl -fsSL https://sentinela.nozaf.ao/instalar.sh | sudo bash"
	[ "$(uname -s)" = Linux ] || die "Sentinela runs on Linux"
	if ! command -v systemctl >/dev/null || [ ! -d /run/systemd/system ]; then die "systemd is required"; fi
	case "$(uname -m)" in
		x86_64|amd64) ARCH=amd64 ;;
		aarch64|arm64) ARCH=arm64 ;;
		*) die "unsupported architecture $(uname -m) (amd64 and arm64 only)" ;;
	esac
	OS=linux
	if [ -r /etc/os-release ]; then
		# shellcheck disable=SC1091
		OS=$(. /etc/os-release && printf '%s-%s' "${ID:-linux}" "${VERSION_ID:-}")
	fi
	OS=$(printf '%s' "$OS" | tr -c 'a-zA-Z0-9._-' '-' | tr '[:upper:]' '[:lower:]' | cut -c1-40)
	OS=${OS%-}
}

# ---------------------------------------------------------------- crowdsec

detect_crowdsec() {
	MODE='' CONTAINER='' LAPI_URL='' METRICS_URL=''
	if command -v cscli >/dev/null && systemctl list-unit-files crowdsec.service >/dev/null 2>&1 \
		&& systemctl is-enabled crowdsec >/dev/null 2>&1; then
		MODE='exec'
	elif command -v docker >/dev/null && docker info >/dev/null 2>&1; then
		CONTAINER=$(docker ps --format '{{.Names}} {{.Image}}' | awk '$2 ~ /crowdsecurity\/crowdsec/ {print $1; exit}')
		[ -n "$CONTAINER" ] && MODE=docker
	fi
	return 0
}

ensure_crowdsec() {
	step "CrowdSec"
	detect_crowdsec
	if command -v docker >/dev/null; then info "Docker: $(docker --version 2>/dev/null | head -1)"; else info "Docker: not installed (not needed when CrowdSec runs on the host)"; fi
	case "$MODE" in
	exec)
		ok "CrowdSec on the host ($(cscli version 2>/dev/null | sed -n 's/^version: *//p' | head -1))"
		systemctl is-active --quiet crowdsec || { systemctl start crowdsec; sleep 3; }
		systemctl is-active --quiet crowdsec || die "the crowdsec service does not start: journalctl -u crowdsec"
		;;
	docker)
		ok "CrowdSec in the Docker container '$CONTAINER'"
		;;
	*)
		warn "CrowdSec was not found (no cscli on the host and no crowdsecurity/crowdsec container)."
		info "Sentinela can install it from the official CrowdSec package repository (packagecloud)."
		confirm_install "CrowdSec" || die "install CrowdSec first: https://docs.crowdsec.net/docs/getting_started/install_crowdsec"
		need_cmd curl curl
		curl -fsSL https://install.crowdsec.net | sh
		pkg_install crowdsec
		systemctl enable --now crowdsec || true
		sleep 3
		systemctl is-active --quiet crowdsec || die "CrowdSec was installed but does not start. A common cause is port 8080 already in use:
    change listen_uri in /etc/crowdsec/config.yaml and url in /etc/crowdsec/local_api_credentials.yaml,
    start it (systemctl restart crowdsec) and run this installer again. Details: journalctl -u crowdsec"
		detect_crowdsec
		[ "$MODE" = exec ] || die "CrowdSec did not install correctly"
		ok "CrowdSec installed. Add a bouncer to actually block traffic: https://docs.crowdsec.net/u/bouncers/intro"
		;;
	esac
	find_endpoints
}

# Where the Local API and the Prometheus endpoint listen.
find_endpoints() {
	local cfg=/etc/crowdsec/config.yaml creds=/etc/crowdsec/local_api_credentials.yaml addr port
	if [ "$MODE" = exec ]; then
		LAPI_URL=$(sed -n 's/^url: *//p' "$creds" 2>/dev/null | tr -d '"'"'" | head -1)
		[ -n "$LAPI_URL" ] || LAPI_URL=http://127.0.0.1:8080
		LAPI_URL=${LAPI_URL%/}
		addr=$(awk '/^prometheus:/{p=1;next} p&&/^[^ ]/{p=0} p&&/listen_addr:/{print $2}' "$cfg" 2>/dev/null | tr -d '"'"'" || true)
		port=$(awk '/^prometheus:/{p=1;next} p&&/^[^ ]/{p=0} p&&/listen_port:/{print $2}' "$cfg" 2>/dev/null | tr -d '"'"'" || true)
		[ -z "$addr" ] || [ "$addr" = 0.0.0.0 ] && addr=127.0.0.1
		METRICS_URL="http://$addr:${port:-6060}/metrics"
	else
		local p
		p=$(docker port "$CONTAINER" 8080/tcp 2>/dev/null | head -1)
		[ -n "$p" ] || die "the container '$CONTAINER' does not publish the Local API (8080/tcp) on the host. Add for example
      ports: [\"127.0.0.1:8080:8080\", \"127.0.0.1:6060:6060\"]
    to its service and start it again."
		LAPI_URL="http://127.0.0.1:${p##*:}"
		p=$(docker port "$CONTAINER" 6060/tcp 2>/dev/null | head -1)
		if [ -n "$p" ]; then METRICS_URL="http://127.0.0.1:${p##*:}/metrics"; else METRICS_URL=; warn "metrics (6060/tcp) are not published: the AppSec page will stay empty"; fi
	fi
	# cscli checks the real Local API with its own credentials; a bare HTTP answer could come from another program.
	cs lapi status >/dev/null 2>&1 || die "CrowdSec's Local API does not answer (cscli lapi status). Is CrowdSec running?"
	curl -sS -m 5 -o /dev/null "$LAPI_URL/" 2>/dev/null || die "the Local API is not reachable on $LAPI_URL from the host"
	ok "Local API: $LAPI_URL"
	if [ -n "$METRICS_URL" ]; then
		if curl -fsS -m 5 "$METRICS_URL" 2>/dev/null | grep '^cs_' >/dev/null; then ok "metrics: $METRICS_URL"
		else warn "metrics do not answer on $METRICS_URL (enable prometheus in /etc/crowdsec/config.yaml); continuing"; fi
	fi
}

cs() {  # cscli where CrowdSec runs
	if [ "$MODE" = docker ]; then docker exec "$CONTAINER" cscli "$@"; else cscli "$@"; fi
}

# ---------------------------------------------------------------- release files

latest_version() {
	local u
	u=$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest") || die "cannot reach github.com"
	u=${u##*/tag/v}
	[[ "$u" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "could not find the latest release"
	printf '%s' "$u"
}

fetch() {  # fetch NAME -> $TMP/NAME
	if [ -n "${SENTINELA_FROM:-}" ]; then
		cp "$SENTINELA_FROM/$1" "$TMP/$1" 2>/dev/null || die "$1 is not in $SENTINELA_FROM"
	else
		curl -fsSL --retry 3 --proto '=https' --tlsv1.2 -o "$TMP/$1" \
			"https://github.com/$REPO/releases/download/v$VERSION/$1" || die "download failed: $1 (v$VERSION)"
	fi
}

# Downloads the binary and this script, and accepts them only if SHA256SUMS is signed by the release key.
download_release() {
	need_cmd curl curl
	need_cmd sha256sum coreutils
	need_cmd gpg gnupg
	TMP=$(mktemp -d)
	if [ -n "${SENTINELA_VERSION:-}" ]; then VERSION=${SENTINELA_VERSION#v}
	elif [ -n "${SENTINELA_FROM:-}" ]; then VERSION=$(head -1 "$SENTINELA_FROM/VERSION" 2>/dev/null | tr -d ' \r' || true)
	else VERSION=$(latest_version)
	fi
	[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "invalid version '$VERSION'"
	step "Sentinela $VERSION ($ARCH)"
	ASSET=sentinela-linux-$ARCH
	fetch SHA256SUMS; fetch SHA256SUMS.asc; fetch "$ASSET"; fetch instalar.sh

	mkdir -m 0700 "$TMP/gnupg"
	printf '%s\n' "$RELEASE_KEY" | gpg --batch --quiet --homedir "$TMP/gnupg" --import 2>/dev/null || die "could not load the release key"
	local status
	status=$(gpg --batch --homedir "$TMP/gnupg" --status-fd 1 --verify "$TMP/SHA256SUMS.asc" "$TMP/SHA256SUMS" 2>/dev/null) \
		|| die "SHA256SUMS has no valid signature. Nothing was installed."
	grep -q "^\[GNUPG:\] VALIDSIG $FPR " <<<"$status" || die "SHA256SUMS is not signed by the release key $FPR. Nothing was installed."
	ok "signature of SHA256SUMS: valid (release key ${FPR: -16})"
	(cd "$TMP" && grep -E "  ($ASSET|instalar\.sh)\$" SHA256SUMS | sha256sum -c --quiet -) \
		|| die "checksum mismatch. Nothing was installed."
	[ "$(cd "$TMP" && grep -cE "  ($ASSET|instalar\.sh)\$" SHA256SUMS)" = 2 ] || die "SHA256SUMS does not list $ASSET and instalar.sh"
	ok "SHA256 of $ASSET and instalar.sh: match"
	chmod 0755 "$TMP/$ASSET"
	[ "$("$TMP/$ASSET" version)" = "$VERSION" ] || die "the binary does not report version $VERSION"
}

install_files() {
	install -m 0755 -o root -g root "$TMP/$ASSET" "$BIN.new" && mv -f "$BIN.new" "$BIN"
	install -m 0755 -o root -g root "$TMP/instalar.sh" "$ADMIN.new" && mv -f "$ADMIN.new" "$ADMIN"
	ok "$BIN ($("$BIN" version)) and $ADMIN"
}

# ---------------------------------------------------------------- configuration

is_public_addr() {  # true unless loopback, RFC 1918, CGNAT, link-local or ULA
	local h=${1%:*}
	h=${h#[}; h=${h%]}
	case "$h" in
		127.*|localhost|::1|10.*|192.168.*|169.254.*|fd*|fc*) return 1 ;;
		172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 1 ;;
		100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 1 ;;
	esac
	return 0
}

choose_listen() {
	LISTEN=${SENTINELA_LISTEN:-$(envget SENTINELA_LISTEN)}
	if [ -z "$LISTEN" ]; then
		LISTEN=$DEFAULT_LISTEN
		local vpn
		vpn=$(ip -4 -o addr show 2>/dev/null | awk '$2 ~ /^(wg|tailscale|tun)/ {split($4,a,"/"); print $2" "a[1]; exit}' || true)
		if [ -n "$vpn" ] && ask "Listen on the VPN address ${vpn#* } (${vpn%% *}) instead of $DEFAULT_LISTEN?" n; then
			LISTEN="${vpn#* }:8095"
		fi
	fi
	[[ "$LISTEN" =~ ^(\[[0-9a-fA-F:]+\]|[0-9.]+|localhost):[0-9]{1,5}$ ]] || die "SENTINELA_LISTEN must look like 127.0.0.1:8095, got '$LISTEN'"
	if [ "${LISTEN%:*}" = 0.0.0.0 ] || [ "${LISTEN%:*}" = "[::]" ] || is_public_addr "$LISTEN"; then
		[ "${SENTINELA_ALLOW_PUBLIC:-0}" = 1 ] || die "$LISTEN would expose the interface to the Internet. Use 127.0.0.1 or a VPN address,
    or put it behind a TLS reverse proxy with SSO. To do it anyway: SENTINELA_ALLOW_PUBLIC=1."
		warn "listening on $LISTEN: make sure a firewall and TLS protect it"
	fi
}

write_env() {
	local old
	old=$(envget SENTINELA_CSCLI_MODE)
	if [ -f "$ENVF" ] && [ -n "$old" ] && [ "$old" != none ] && [ "$old" != "$MODE" ]; then
		cp -a "$ENVF" "$ENVF.$(date +%Y%m%d%H%M%S)"
		warn "CrowdSec now runs in mode '$MODE' (was '$old'): rewriting $ENVF, the old copy is kept next to it"
		rm -f "$ENVF"
	fi
	if [ -f "$ENVF" ]; then
		# Keep local changes; refresh only what this script detects.
		sed -i -e "s|^SENTINELA_LISTEN=.*|SENTINELA_LISTEN=$LISTEN|" -e "s|^SENTINELA_LAPI_URL=.*|SENTINELA_LAPI_URL=$LAPI_URL|" "$ENVF"
		[ -n "$METRICS_URL" ] && sed -i "s|^SENTINELA_METRICS_URL=.*|SENTINELA_METRICS_URL=$METRICS_URL|" "$ENVF"
		ok "kept $ENVF (listen $LISTEN, Local API $LAPI_URL)"
		return
	fi
	local cscli reload docker=
	if [ "$MODE" = exec ]; then
		cscli="SENTINELA_CSCLI_MODE=exec
SENTINELA_CSCLI_COMMAND=sudo -n $(command -v cscli)"
		reload="SENTINELA_RELOAD_COMMAND=sudo -n $(command -v systemctl) reload crowdsec"
	else
		cscli="SENTINELA_CSCLI_MODE=docker
SENTINELA_DOCKER_CONTAINER=$CONTAINER"
		reload=
		docker="SENTINELA_DOCKER_HOST=unix:///var/run/docker.sock"
	fi
	( umask 027; cat >"$ENVF" <<EOF
# Sentinela configuration, written by instalar.sh. Change it, then: sudo systemctl restart sentinela
# All variables: https://github.com/$REPO#configuration
SENTINELA_LISTEN=$LISTEN
SENTINELA_AUTH_MODE=local
SENTINELA_USERS_FILE=$USERS
SENTINELA_LAPI_URL=$LAPI_URL
SENTINELA_LAPI_MACHINE_ID=sentinela
SENTINELA_LAPI_PASSWORD_FILE=$ETC/lapi_password
SENTINELA_METRICS_URL=$METRICS_URL
$cscli
$reload
$docker
# Plain HTTP on localhost or a VPN. Behind a TLS reverse proxy set this to true.
SENTINELA_COOKIE_SECURE=false
SENTINELA_SESSION_TTL=8h
EOF
	)
	chown root:sentinela "$ENVF"
	ok "wrote $ENVF"
}

setup_system() {
	step "System user, configuration and Local API machine"
	id sentinela >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin sentinela
	install -d -m 0750 -o root -g sentinela "$ETC"
	ok "system user sentinela, $ETC"
	write_env

	if [ -s "$ETC/lapi_password" ] && cs machines list -o json 2>/dev/null | grep '"sentinela"' >/dev/null; then
		ok "Local API machine 'sentinela' already registered"
	else
		local f pw
		f=$(mktemp "$TMP/lapi.XXXXXX")
		if [ "$MODE" = docker ]; then
			docker exec "$CONTAINER" cscli machines add sentinela --auto --force -f - >"$f" 2>/dev/null \
				|| die "cscli machines add failed in the container"
		else
			cscli machines add sentinela --auto --force -f "$f" >/dev/null 2>&1 || die "cscli machines add failed"
		fi
		pw=$(sed -n 's/^password: *//p' "$f" | tr -d '"'"'" | head -1)
		rm -f "$f"
		[ -n "$pw" ] || die "the Local API password was not generated"
		( umask 027; printf '%s\n' "$pw" >"$ETC/lapi_password" )
		unset pw
		chown root:sentinela "$ETC/lapi_password"; chmod 0640 "$ETC/lapi_password"
		ok "Local API machine 'sentinela' registered (password kept in $ETC/lapi_password, never shown)"
	fi

	if [ "$MODE" = exec ]; then
		local tmp
		need_cmd sudo sudo
		tmp=$(mktemp "$TMP/sudoers.XXXXXX")
		cat >"$tmp" <<EOF
# Sentinela may run cscli and reload CrowdSec, nothing else. Written by instalar.sh.
Defaults:sentinela !requiretty, env_reset
sentinela ALL=(root) NOPASSWD: $(command -v cscli), $(command -v systemctl) reload crowdsec
EOF
		visudo -cf "$tmp" >/dev/null || die "the sudoers rule is invalid"
		install -m 0440 -o root -g root "$tmp" "$SUDOERS"
		sudo -u sentinela sudo -n "$(command -v cscli)" version >/dev/null 2>&1 || die "sudo for the sentinela user does not work"
		ok "sudo limited to cscli and 'systemctl reload crowdsec' ($SUDOERS)"
	else
		warn "CrowdSec runs in Docker: Sentinela needs the Docker socket to run cscli in '$CONTAINER'."
		warn "Membership of the docker group is equivalent to root on this host."
		if id -nG sentinela | grep -qw docker; then ok "sentinela is already in the docker group"
		elif [ "$(envget SENTINELA_CSCLI_MODE)" = none ]; then info "Docker access was declined before (SENTINELA_CSCLI_MODE=none): kept"
		elif ask "Add the sentinela user to the docker group?" n; then usermod -aG docker sentinela; ok "added to the docker group"
		else
			sed -i 's/^SENTINELA_CSCLI_MODE=.*/SENTINELA_CSCLI_MODE=none/' "$ENVF"
			warn "no Docker access: decisions and alerts work, hub and allowlists pages will be disabled"
		fi
	fi
}

write_unit() {
	local after="network-online.target"
	[ "$MODE" = exec ] && after="$after crowdsec.service"
	[ "$MODE" = docker ] && after="$after docker.service"
	case "${LISTEN%:*}" in 127.*|localhost|\[::1\]) ;; *) ip -o addr show wg0 >/dev/null 2>&1 && after="$after wg-quick@wg0.service" ;; esac
	cat >"$UNIT.new" <<EOF
# Written by instalar.sh (Sentinela). Local changes: systemctl edit sentinela
[Unit]
Description=Sentinela, web interface for CrowdSec
Documentation=https://github.com/$REPO
After=$after
Wants=network-online.target

[Service]
User=sentinela
Group=sentinela
EnvironmentFile=$ENVF
ExecStart=$BIN serve
Restart=on-failure
RestartSec=5

# sudo (for cscli) needs to change user, so NoNewPrivileges stays off. Everything else is closed.
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
SystemCallArchitectures=native
ReadWritePaths=-/etc/crowdsec -/var/lib/crowdsec /var/log -/var/lib/sudo /run
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF
	mv -f "$UNIT.new" "$UNIT"
	systemctl daemon-reload
}

# ---------------------------------------------------------------- accounts

users_count() { local n=0; [ -f "$USERS" ] && n=$(grep -cE '^[^#[:space:]][^:]*:' "$USERS" || true); echo "${n:-0}"; }

create_user() {  # create_user LOGIN ROLE
	local login=$1 role=${2:-admin} pw pw2 hash out secret uri totp=
	[[ "$login" =~ ^[a-zA-Z0-9._@-]{1,64}$ ]] || die "invalid user name '$login'"
	[[ "$role" = admin || "$role" = viewer ]] || die "role must be admin or viewer"
	has_tty || die "creating an account needs a terminal (the password is typed, never passed on the command line)"
	{
		echo
		echo "    Password for '$login' (12 to 72 characters). It is not shown while you type."
	} >/dev/tty
	read -rsp "    Password: " pw </dev/tty; echo >/dev/tty
	read -rsp "    Again:    " pw2 </dev/tty; echo >/dev/tty
	[ "$pw" = "$pw2" ] || die "the passwords do not match"
	hash=$(printf '%s\n' "$pw" | "$BIN" hash-password 2>/dev/null) || die "password refused (12 to 72 characters)"
	unset pw pw2
	if ask "Require a one-time code (TOTP) from an authenticator app? Strongly recommended." y; then
		out=$("$BIN" totp-secret -issuer "Sentinela $(hostname -s 2>/dev/null || echo)" "$login")
		secret=$(sed -n 's/^secret: *//p' <<<"$out")
		uri=$(sed -n 's/^uri: *//p' <<<"$out")
		[ -n "$secret" ] || die "the TOTP secret was not generated"
		totp=":$secret"
	fi
	touch "$USERS"
	( umask 027; { grep -v "^${login}:" "$USERS" || true; printf '%s:%s:%s%s\n' "$login" "$role" "$hash" "$totp"; } >"$USERS.new" )
	chown root:sentinela "$USERS.new"; chmod 0640 "$USERS.new"; mv -f "$USERS.new" "$USERS"
	unset hash
	if [ -n "$totp" ]; then
		# Shown on the terminal only, never written to a log.
		{
			echo
			echo "    Add this account to your authenticator app (scan the QR code or type the secret):"
			command -v qrencode >/dev/null && qrencode -t ansiutf8 "$uri"
			echo "    secret: $secret"
			echo "    It will not be shown again. To replace it: sudo sentinela-admin user $login"
		} >/dev/tty
	fi
	unset secret uri out
	ok "account '$login' ($role) saved"
}

ensure_account() {
	step "Account"
	if [ "$(users_count)" -gt 0 ]; then ok "$(users_count) account(s) in $USERS: kept"; return 0; fi
	if ! has_tty; then
		warn "no terminal: no account created. Create one with: sudo sentinela-admin user admin"
		return 1
	fi
	if ! command -v qrencode >/dev/null && ask "Install qrencode to show the TOTP setup as a QR code?" y; then pkg_install qrencode >/dev/null 2>&1 || true; fi
	local login
	printf '    Name of the first administrator [admin]: ' >/dev/tty
	IFS= read -r login </dev/tty || login=
	create_user "${login:-admin}" admin
}

# ---------------------------------------------------------------- service

start_service() {
	step "Service"
	systemctl enable sentinela >/dev/null 2>&1
	systemctl restart sentinela
	local port=${LISTEN##*:} host=${LISTEN%:*}
	[ "$host" = 0.0.0.0 ] && host=127.0.0.1
	[ "$host" = "[::]" ] && host="[::1]"
	for _ in $(seq 1 20); do
		curl -fsS -m 3 -o /dev/null "http://$host:$port/healthz" 2>/dev/null && { ok "running on http://$LISTEN"; return 0; }
		sleep 1
	done
	journalctl -u sentinela -n 20 --no-pager >&2 || true
	die "Sentinela did not answer on http://$LISTEN/healthz"
}

# ---------------------------------------------------------------- telemetry

# One anonymous message per event, only with consent, only from an interactive terminal.
# Body: {"id","projecto","versao","so","arq","evento"}; no IP, no host name.
telemetry() {  # telemetry install|update|uninstall
	local event=$1 ev choice id body
	case "$event" in install) ev=instalar ;; update) ev=actualizar ;; uninstall) ev=desinstalar ;; *) return 0 ;; esac
	[ "${SENTINELA_TELEMETRIA:-1}" = 0 ] && return 0
	has_tty || return 0
	choice=$(cat "$ETC/telemetria" 2>/dev/null || true)
	if [ -z "$choice" ]; then
		[ "$event" = install ] || return 0
		{
			echo
			echo "    Help the project count its installations?"
			echo "    One anonymous message: a random id, the version ($VERSION), the system ($OS, $ARCH)"
			echo "    and the event. No IP address, host name or configuration. You can stop it at any"
			echo "    time with: echo nao | sudo tee $ETC/telemetria"
		} >/dev/tty
		if ask "Send it?" n; then choice=sim; else choice=nao; fi
		printf '%s\n' "$choice" >"$ETC/telemetria"
	fi
	[ "$choice" = sim ] || return 0
	if [ ! -s "$ETC/id" ]; then
		( umask 022; cat /proc/sys/kernel/random/uuid >"$ETC/id" )
	fi
	id=$(tr -dc 'a-f0-9-' <"$ETC/id" | cut -c1-36)
	[[ "$id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]] || return 0
	body=$(printf '{"id":"%s","projecto":"sentinela","versao":"%s","so":"%s","arq":"%s","evento":"%s"}' \
		"$id" "$VERSION" "$OS" "$ARCH" "$ev")
	if curl -fsS -m 5 -o /dev/null -X POST -H 'Content-Type: application/json' --data "$body" "$TELEMETRY_URL" 2>/dev/null; then
		ok "anonymous $ev event sent. Thank you."
	else
		info "(the anonymous count could not be sent; nothing else happens)"
	fi
}

# ---------------------------------------------------------------- commands

support_note() {
	echo
	echo "    Sentinela is free and maintained in spare time. If it helps you, support it:"
	echo "    $SUPPORT_URL"
	echo "    Ideas and questions: https://github.com/$REPO/discussions"
}

cmd_install() {
	local event=${1:-install}
	check_platform
	echo "${B}Sentinela installer${N} - web interface for CrowdSec"
	[ -x "$BIN" ] && [ "$event" = install ] && info "already installed ($("$BIN" version)): checking and repairing"
	ensure_crowdsec
	download_release
	if [ "$event" = update ] && [ -x "$BIN" ] && [ "$("$BIN" version)" = "$VERSION" ]; then
		ok "already on $VERSION"
	fi
	choose_listen
	setup_system
	install_files
	write_unit
	local have_account=0
	ensure_account && have_account=1
	if [ "$have_account" = 1 ]; then start_service
	else systemctl enable sentinela >/dev/null 2>&1; info "the service will start after the first account is created"
	fi
	telemetry "$event"

	step "Done"
	case "${LISTEN%:*}" in
		127.*|localhost|\[::1\])
			info "Open it through an SSH tunnel from your computer:"
			info "  ssh -N -L 8095:$LISTEN ${SUDO_USER:-you}@<this-server>   then http://localhost:8095" ;;
		*) info "Open http://$LISTEN (from the VPN or private network)" ;;
	esac
	info "Manage it: sudo sentinela-admin status | update | user NAME | uninstall"
	support_note
}

cmd_update() {
	[ -x "$BIN" ] || die "Sentinela is not installed. Install it with: curl -fsSL https://sentinela.nozaf.ao/instalar.sh | sudo bash"
	cmd_install update
}

cmd_user() {
	check_platform
	[ -x "$BIN" ] || die "Sentinela is not installed"
	[ -n "${1:-}" ] || die "usage: sentinela-admin user NAME [admin|viewer]"
	install -d -m 0750 -o root -g sentinela "$ETC"
	create_user "$1" "${2:-admin}"
	LISTEN=$(envget SENTINELA_LISTEN); LISTEN=${LISTEN:-$DEFAULT_LISTEN}
	start_service
	info "Accounts are read at start-up: open sessions were closed."
}

cmd_uninstall() {
	check_platform
	[ -x "$BIN" ] || [ -f "$UNIT" ] || { ok "Sentinela is not installed"; return 0; }
	if has_tty; then ask "Remove Sentinela from this server?" n || die "nothing changed"
	elif [ "${SENTINELA_YES:-0}" != 1 ]; then die "run in a terminal, or set SENTINELA_YES=1"
	fi
	VERSION=$("$BIN" version 2>/dev/null || echo 0.0.0); ARCH=${ARCH:-amd64}
	telemetry uninstall
	step "Removing"
	systemctl disable --now sentinela >/dev/null 2>&1 || true
	rm -f "$UNIT" "$SUDOERS" "$BIN" "$ADMIN"
	systemctl daemon-reload
	detect_crowdsec
	[ -n "$MODE" ] && cs machines delete sentinela >/dev/null 2>&1 && ok "Local API machine 'sentinela' deleted"
	if [ "${SENTINELA_PURGE:-0}" = 1 ]; then
		rm -rf "$ETC"; ok "deleted $ETC"
		userdel sentinela >/dev/null 2>&1 || true
	else
		rm -f "$ETC/lapi_password"
		info "kept $ETC (accounts). Delete it with SENTINELA_PURGE=1."
	fi
	ok "Sentinela removed. CrowdSec was not touched."
}

cmd_status() {
	check_platform
	step "Sentinela"
	if [ -x "$BIN" ]; then ok "binary: $BIN $("$BIN" version)"; else warn "not installed"; return 0; fi
	info "service: $(systemctl is-active sentinela 2>/dev/null || true), $(systemctl is-enabled sentinela 2>/dev/null || true)"
	info "listen: $(envget SENTINELA_LISTEN)"
	info "cscli: $(envget SENTINELA_CSCLI_MODE)"
	info "accounts: $(cut -d: -f1,2 "$USERS" 2>/dev/null | tr '\n' ' ')"
	info "telemetry: $(cat "$ETC/telemetria" 2>/dev/null || echo 'not asked')"
	local l
	l=$(envget SENTINELA_LISTEN)
	[ -n "$l" ] && info "health: $(curl -s -m 3 -o /dev/null -w '%{http_code}' "http://${l/0.0.0.0/127.0.0.1}/healthz" || true)"
}

main() {
	# Questions are read from /dev/tty. No command below may read stdin: with curl | bash it is the script itself.
	exec </dev/null
	local cmd=${1:-install}
	[ $# -gt 0 ] && shift
	case "$cmd" in
		install|instalar) cmd_install install ;;
		update|upgrade|actualizar|atualizar) cmd_update ;;
		uninstall|remove|desinstalar) cmd_uninstall ;;
		user|utilizador|usuario) cmd_user "$@" ;;
		status|estado) cmd_status ;;
		-h|--help|help|ajuda) sed -n '2,36p' "${BASH_SOURCE[0]:-/dev/null}" 2>/dev/null | sed 's/^# \{0,1\}//' || true ;;
		*) die "unknown command '$cmd' (install, update, uninstall, user, status)" ;;
	esac
}

# Everything above only defines functions: a partial download cannot run half a script.
main "$@"
