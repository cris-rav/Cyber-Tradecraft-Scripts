#!/usr/bin/env bash
#
# setup-auditd-wazuh.sh
#
# Installs auditd on a Debian/Ubuntu box, loads the Neo23x0/auditd ruleset with
# its keys rewritten to the ones the DEFAULT Wazuh ruleset alerts on, and makes
# sure the Wazuh agent forwards the audit log (plus web logs if present).
#
# Usage (run as root):
#   ./setup-auditd-wazuh.sh [install] [options]   deploy everything (default)
#   ./setup-auditd-wazuh.sh verify    [options]   check the chain, generate test events
#   ./setup-auditd-wazuh.sh rollback              restore the original configs
#   ./setup-auditd-wazuh.sh flush                 drop the backlog (stop agent, clear audit.log, restart)
#
# Options:
#   --rules FILE         use a local copy of Neo23x0's audit.rules (offline use)
#   --url URL            download the ruleset from a different URL
#   --webroot DIR        web root to watch for writes (default: /var/www)
#   --no-webroot-watch   do not add a watch on the web root
#   --no-weblogs         do not add apache/nginx access/error logs to the agent
#   --no-test            do not generate test events in verify
#   -h, --help           show this help
#

set -uo pipefail

RULES_URL="https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules"
RULES_FILE=""
WEBROOT="/var/www"
WEBROOT_WATCH=1
WEBLOGS=1
RUN_TESTS=1

OSSEC_CONF="/var/ossec/etc/ossec.conf"
OSSEC_LOG="/var/ossec/logs/ossec.log"
AUDIT_CONF="/etc/audit/auditd.conf"
RULES_D="/etc/audit/rules.d"
OUT_RULES="$RULES_D/10-neo23x0-wazuh.rules"
EXEC_RULES="$RULES_D/50-execve-filtered.rules"
WEB_RULES="$RULES_D/99-webroot.rules"
# Executables whose execve events are pure desktop/session noise. Add more if needed.
# (Do NOT add shells such as dash/bash/sh: web shells run through them.)
EXEC_EXCLUDES=(
  /usr/lib/systemd/systemd-executor /usr/lib/systemd/systemd-user-runtime-dir
  /usr/bin/gpg-agent /usr/bin/gpgconf /usr/bin/dbus-daemon /usr/bin/mawk
  /usr/bin/pipewire /usr/bin/pipewire-pulse /usr/bin/wireplumber /usr/bin/mpris-proxy
)
BACKUP="/root/auditd-wazuh-backup"
LOG="/var/log/auditd-wazuh-setup.log"
SRC_RULES="/tmp/neo23x0-audit.rules"
PRE_CONF="/tmp/ossec.conf.pre-auditd"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_CHANGED=0

info() { echo "[+] $*"; }
warn() { echo "[!] $*" >&2; }
die()  { echo "[x] $*" >&2; exit 1; }

usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------- install ---

install_pkgs() {
  if command -v auditctl >/dev/null 2>&1 && command -v augenrules >/dev/null 2>&1; then
    info "auditd already installed"
  else
    command -v apt-get >/dev/null 2>&1 || die "apt-get not found; install auditd manually"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || warn "apt-get update failed (offline?), trying install anyway"
    apt-get install -y auditd || die "auditd install failed"
    apt-get install -y audispd-plugins >/dev/null 2>&1 || true
  fi
  systemctl enable --now auditd >/dev/null 2>&1 || true
}

backup_originals() {
  [[ -d $BACKUP/original ]] && return 0   # only ever back up the pristine state
  mkdir -p "$BACKUP/original/rules.d"
  cp -a "$RULES_D"/. "$BACKUP/original/rules.d/" 2>/dev/null
  cp -a "$AUDIT_CONF" "$BACKUP/original/" 2>/dev/null
  [[ -f $OSSEC_CONF ]] && cp -a "$OSSEC_CONF" "$BACKUP/original/"
  info "Original configs backed up to $BACKUP/original"
}

set_conf() {  # set_conf key value  (in auditd.conf)
  local k=$1 v=$2
  if grep -qE "^[[:space:]]*$k[[:space:]]*=" "$AUDIT_CONF"; then
    sed -i -E "s|^[[:space:]]*$k[[:space:]]*=.*|$k = $v|" "$AUDIT_CONF"
  else
    echo "$k = $v" >> "$AUDIT_CONF"
  fi
}

tune_auditd_conf() {
  # Neo23x0 is chatty: cap log size so the disk cannot fill up.
  set_conf max_log_file 50
  set_conf num_logs 5
  set_conf max_log_file_action ROTATE
  systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null \
    || warn "could not restart auditd to apply auditd.conf"
}

get_rules() {
  if [[ -n $RULES_FILE ]]; then
    [[ -f $RULES_FILE ]] || die "--rules file not found: $RULES_FILE"
    cp "$RULES_FILE" "$SRC_RULES" || die "cannot copy $RULES_FILE"
    info "Using ruleset from $RULES_FILE"
  elif [[ -f $SCRIPT_DIR/audit.rules ]]; then
    cp "$SCRIPT_DIR/audit.rules" "$SRC_RULES" || die "cannot copy local audit.rules"
    info "Using pre-staged $SCRIPT_DIR/audit.rules"
  else
    info "Downloading ruleset from $RULES_URL"
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL --max-time 30 "$RULES_URL" -o "$SRC_RULES" || die "download failed (offline? use --rules FILE)"
    elif command -v wget >/dev/null 2>&1; then
      wget -q -T 30 -O "$SRC_RULES" "$RULES_URL" || die "download failed (offline? use --rules FILE)"
    else
      die "neither curl nor wget available; use --rules FILE"
    fi
  fi
  grep -qE '^-(w|a) ' "$SRC_RULES" || die "$SRC_RULES does not look like an audit rules file"
}

build_rules() {
  # Remove other rule files so nothing conflicts (originals are backed up).
  local f
  for f in "$RULES_D"/*.rules; do
    [[ -e $f ]] || continue
    [[ $f == "$OUT_RULES" || $f == "$EXEC_RULES" || $f == "$WEB_RULES" ]] && continue
    rm -f "$f"
  done

  # "-i" ignores load errors (missing paths, unsupported syscalls) instead of
  # aborting the whole load. Keys are rewritten so the default Wazuh rules
  # (audit-wazuh-w for watches, audit-wazuh-c for execve) fire; an active
  # "-e 2" (immutable) is commented out so you can still change rules live.
  {
    echo "# Generated by setup-auditd-wazuh.sh from Neo23x0/auditd with Wazuh keys"
    echo "-i"
    sed -E \
      -e '/^-w \/var\/(log\/)?audit\//d' \
      -e '/-k process_creation/d' \
      -e 's/^-e[[:space:]]+2/#&/' \
      -e '/^-w /{/[[:space:]]-k[[:space:]]/!s/[[:space:]]*$/ -k audit-wazuh-w/}' \
      -e '/^-w /s/-k[[:space:]]+[^[:space:]]+[[:space:]]*$/-k audit-wazuh-w/' \
      -e '/^-a .*execve/{/[[:space:]]-k[[:space:]]/!s/[[:space:]]*$/ -k audit-wazuh-c/}' \
      -e '/^-a .*execve/s/-k[[:space:]]+[^[:space:]]+[[:space:]]*$/-k audit-wazuh-c/' \
      "$SRC_RULES"
  } > "$OUT_RULES"
  info "Wrote $OUT_RULES ($(grep -c 'audit-wazuh' "$OUT_RULES") rules carry Wazuh keys)"

  build_execve_rules

  rm -f "$WEB_RULES"
  if (( WEBROOT_WATCH )) && [[ -d $WEBROOT ]]; then
    if grep -qE "^-w[[:space:]]+${WEBROOT%/}/?[[:space:]]" "$OUT_RULES"; then
      info "Web root $WEBROOT already watched by the ruleset"
    else
      echo "-w $WEBROOT -p wa -k audit-wazuh-w" > "$WEB_RULES"
      info "Added watch on $WEBROOT"
    fi
  fi
}

build_execve_rules() {
  local e uid
  {
    echo "# Filtered execve logging (replaces Neo23x0's unfiltered process_creation)"
    for e in "${EXEC_EXCLUDES[@]}"; do
      echo "-a never,exit -F arch=b64 -S execve -S execveat -F exe=$e"
      echo "-a never,exit -F arch=b32 -S execve -S execveat -F exe=$e"
    done
    # Web/service user: every exec (this is what catches web shells)
    if uid=$(id -u www-data 2>/dev/null); then
      echo "-a always,exit -F arch=b64 -S execve -S execveat -F euid=$uid -k audit-wazuh-c"
      echo "-a always,exit -F arch=b32 -S execve -S execveat -F euid=$uid -k audit-wazuh-c"
    fi
    # Interactive logins (ssh/console/sudo from a login): auid is set
    echo "-a always,exit -F arch=b64 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k audit-wazuh-c"
    echo "-a always,exit -F arch=b32 -S execve -S execveat -F auid>=1000 -F auid!=-1 -k audit-wazuh-c"
  } > "$EXEC_RULES"
  info "Wrote $EXEC_RULES (execve limited to www-data and logged-in users, ${#EXEC_EXCLUDES[@]} noisy exes excluded)"
}

load_rules() {
  if auditctl -s 2>/dev/null | grep -qE 'enabled[ =]+2'; then
    warn "Audit config is LOCKED (enabled 2). Rules written but need a reboot to apply."
    return 0
  fi
  if ! augenrules --load; then
    warn "augenrules --load failed, trying auditctl -R"
    auditctl -R /etc/audit/audit.rules || warn "rule load failed, check: auditctl -l"
  fi
  info "$(auditctl -l 2>/dev/null | wc -l) audit rules loaded"
}

add_localfile() {  # add_localfile FORMAT LOCATION
  local fmt=$1 loc=$2 tmp
  if grep -qF "<location>$loc</location>" "$OSSEC_CONF"; then
    info "Agent already reads $loc"
    return 0
  fi
  tmp=$(mktemp)
  BLK="  <localfile>
    <log_format>$fmt</log_format>
    <location>$loc</location>
  </localfile>
" awk '/<\/ossec_config>/ && !done { printf "%s", ENVIRON["BLK"]; done=1 } { print }' \
    "$OSSEC_CONF" > "$tmp" && cat "$tmp" > "$OSSEC_CONF"
  rm -f "$tmp"
  CONF_CHANGED=1
  info "Added localfile: $loc ($fmt)"
}

configure_wazuh() {
  if [[ ! -f $OSSEC_CONF ]]; then
    warn "Wazuh agent config not found at $OSSEC_CONF, skipping agent setup"
    return 0
  fi
  grep -q '</ossec_config>' "$OSSEC_CONF" || { warn "$OSSEC_CONF looks malformed, skipping"; return 0; }
  cp -a "$OSSEC_CONF" "$PRE_CONF"

  # Larger agent buffer to absorb bursts (only if the default block is present)
  if grep -qE '<queue_size>[0-9]+</queue_size>' "$OSSEC_CONF"; then
    local q; q=$(grep -oE '<queue_size>[0-9]+' "$OSSEC_CONF" | head -n1 | grep -oE '[0-9]+')
    if (( q < 15000 )); then
      sed -i -E 's|<queue_size>[0-9]+</queue_size>|<queue_size>15000</queue_size>|' "$OSSEC_CONF"
      CONF_CHANGED=1
      info "Agent queue_size raised from $q to 15000"
    fi
  fi

  add_localfile audit /var/log/audit/audit.log
  if (( WEBLOGS )); then
    local f
    for f in /var/log/apache2/access.log /var/log/apache2/error.log /var/log/nginx/access.log; do
      [[ -f $f ]] && add_localfile apache "$f"
    done
  fi

  if (( CONF_CHANGED )); then
    systemctl restart wazuh-agent 2>/dev/null || warn "could not restart wazuh-agent"
    sleep 5
    if ! systemctl is-active --quiet wazuh-agent; then
      warn "wazuh-agent did not come back up; restoring previous ossec.conf"
      cp -a "$PRE_CONF" "$OSSEC_CONF"
      systemctl restart wazuh-agent 2>/dev/null
    fi
  else
    info "ossec.conf unchanged, agent not restarted"
  fi
}

# ----------------------------------------------------------------- verify ---

cmd_verify() {
  echo
  info "=== Verification ==="
  command -v auditctl >/dev/null 2>&1 || die "auditctl not found, run install first"

  systemctl is-active --quiet auditd && info "auditd: running" || warn "auditd: NOT running"
  auditctl -s 2>/dev/null | grep -E 'enabled|lost|backlog_limit' | tr '\n' ' '; echo
  info "Rules loaded: $(auditctl -l 2>/dev/null | wc -l) total, $(auditctl -l 2>/dev/null | grep -c 'audit-wazuh') with Wazuh keys"

  if (( RUN_TESTS )); then
    info "Generating test events (execve as www-data/root, write to web root)"
    if id www-data >/dev/null 2>&1; then
      runuser -u www-data -- /usr/bin/id >/dev/null 2>&1
    else
      /usr/bin/id >/dev/null 2>&1
    fi
    if [[ -d $WEBROOT ]]; then
      local t="$WEBROOT/.auditd-wazuh-test"
      touch "$t" 2>/dev/null && rm -f "$t"
    fi
    sleep 2
  fi

  local c w
  c=$(ausearch -k audit-wazuh-c -ts recent --raw 2>/dev/null | grep -c 'type=SYSCALL')
  w=$(ausearch -k audit-wazuh-w -ts recent --raw 2>/dev/null | grep -c 'type=SYSCALL')
  info "audit.log events in last 10 min: execve(audit-wazuh-c)=$c, watches(audit-wazuh-w)=$w"
  (( c == 0 )) && warn "no execve events found, rules may not be loaded"

  if [[ -f $OSSEC_CONF ]]; then
    local i
    for i in 1 2 3 4 5; do
      tail -n 300 "$OSSEC_LOG" 2>/dev/null | grep -q "Analyzing file: '/var/log/audit/audit.log'" && break
      sleep 2
    done
    if tail -n 300 "$OSSEC_LOG" 2>/dev/null | grep -q "Analyzing file: '/var/log/audit/audit.log'"; then
      info "Agent is reading /var/log/audit/audit.log"
    else
      warn "No 'Analyzing file' line for audit.log in $OSSEC_LOG, check the localfile block"
    fi
    info "Last agent connection status line:"
    grep -E "Connected to the server|Unable to connect|No authentication password|Invalid ID" "$OSSEC_LOG" 2>/dev/null | tail -n 1
  fi

  echo
  info "Dashboard checks (filter by this agent): data.audit.key:audit-wazuh-c  |  data.audit.key:audit-wazuh-w  |  rule.groups:audit"
}

# --------------------------------------------------------------- rollback ---

cmd_rollback() {
  [[ -d $BACKUP/original ]] || die "no backup at $BACKUP/original"
  rm -f "$OUT_RULES" "$EXEC_RULES" "$WEB_RULES"
  cp -a "$BACKUP/original/rules.d/." "$RULES_D/" 2>/dev/null
  [[ -f $BACKUP/original/auditd.conf ]] && cp -a "$BACKUP/original/auditd.conf" "$AUDIT_CONF"
  [[ -f $BACKUP/original/ossec.conf ]] && cp -a "$BACKUP/original/ossec.conf" "$OSSEC_CONF"
  systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null
  augenrules --load >/dev/null 2>&1 || warn "could not reload audit rules (locked? reboot)"
  systemctl restart wazuh-agent 2>/dev/null
  info "Rolled back to original configs (note: ossec.conf is restored wholesale)"
}

# ------------------------------------------------------------------ flush ---

cmd_flush() {
  # Throw away the unread backlog so the agent starts from a clean audit.log.
  # Destroys local audit history, so only use it to recover from a flood.
  warn "Stopping agent and clearing /var/log/audit/audit.log*"
  systemctl stop wazuh-agent 2>/dev/null
  service auditd rotate 2>/dev/null || systemctl kill -s USR1 auditd 2>/dev/null
  sleep 1
  rm -f /var/log/audit/audit.log.[0-9]*
  : > /var/log/audit/audit.log
  systemctl start wazuh-agent 2>/dev/null
  info "Done. Agent restarted on an empty audit.log."
}

# ------------------------------------------------------------------- main ---

CMD=install
if [[ ${1:-} && $1 != -* ]]; then CMD=$1; shift; fi
while [[ $# -gt 0 ]]; do
  case $1 in
    --rules)             RULES_FILE=${2:?--rules needs a file}; shift 2 ;;
    --url)               RULES_URL=${2:?--url needs a URL}; shift 2 ;;
    --webroot)           WEBROOT=${2:?--webroot needs a dir}; shift 2 ;;
    --no-webroot-watch)  WEBROOT_WATCH=0; shift ;;
    --no-weblogs)        WEBLOGS=0; shift ;;
    --no-test)           RUN_TESTS=0; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)                   die "unknown option: $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo $0 ...)"
exec > >(tee -a "$LOG") 2>&1

case $CMD in
  install)
    install_pkgs
    backup_originals
    tune_auditd_conf
    get_rules
    build_rules
    load_rules
    configure_wazuh
    cmd_verify
    ;;
  verify)   cmd_verify ;;
  rollback) cmd_rollback ;;
  flush)    cmd_flush ;;
  *)        die "unknown command: $CMD (install | verify | rollback | flush)" ;;
esac
