#!/usr/bin/env bash
# ksc-integration-with-wazuh-siem — deploy Kaspersky Security Center -> Wazuh integration
# on a Wazuh manager: syslog receiver in ossec.conf, decoder, rules, tests, verification, rollback.
#
#   sudo ./deploy.sh plan                 # show what would change (no changes)
#   sudo ./deploy.sh install [--adopt]    # install / update (idempotent)
#   sudo ./deploy.sh test                 # run sample events through wazuh-logtest
#   sudo ./deploy.sh verify               # check current state (no changes)
#   sudo ./deploy.sh rollback             # remove the integration (or --from-backup DIR)
#
# See README.md for details.
set -Eeuo pipefail
umask 077

readonly VERSION="1.0.0"
readonly PROJECT="ksc-integration-with-wazuh-siem"
readonly MARKER="Managed by ${PROJECT}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly REPO_DECODER="${SCRIPT_DIR}/wazuh/decoders/kaspersky_ksc.xml"
readonly REPO_RULES="${SCRIPT_DIR}/wazuh/rules/kaspersky_ksc_rules.xml"
readonly HELPER="${SCRIPT_DIR}/lib/ossec_remote.py"
readonly TEST_RUNNER="${SCRIPT_DIR}/tests/run_logtest.py"
readonly CONFIG_KEYS="KSC_IP LISTEN_IP SYSLOG_PORT SYSLOG_PROTOCOL OSSEC_DIR SERVICE_NAME BACKUP_ROOT BACKUP_KEEP RULE_ID_MIN RULE_ID_MAX LOG_IGNORE_REGEX AGENT_RECOVERY_TIMEOUT"

# ---------------------------------------------------------------- defaults --
declare -A DEFAULTS=(
  [KSC_IP]=""                      # required: IP of the KSC Administration Server (only allowed sender)
  [LISTEN_IP]=""                   # required: manager IP to bind the syslog port to
  [SYSLOG_PORT]="514"
  [SYSLOG_PROTOCOL]="tcp"
  [OSSEC_DIR]="/var/ossec"
  [SERVICE_NAME]="wazuh-manager"
  [BACKUP_ROOT]="/root/${PROJECT}-backups"
  [BACKUP_KEEP]="10"
  [RULE_ID_MIN]="100700"
  [RULE_ID_MAX]="100799"
  [LOG_IGNORE_REGEX]=""            # extended regex of known unrelated ossec.log errors
  [AGENT_RECOVERY_TIMEOUT]="180"   # seconds to wait for agents to reconnect after restart
)

# --------------------------------------------------------------- state -------
CMD=""
CONFIG_FILE="${SCRIPT_DIR}/config.env"
ADOPT=0
NO_RESTART=0
ASSUME_YES=0
FROM_BACKUP=""
TMP_DIR=""
PYTHON=""
CURRENT_BACKUP=""
CHANGES=0

# --------------------------------------------------------------- logging -----
if [[ -t 1 ]]; then C_RED=$'\e[31m'; C_YEL=$'\e[33m'; C_GRN=$'\e[32m'; C_BLU=$'\e[34m'; C_OFF=$'\e[0m'
else C_RED=""; C_YEL=""; C_GRN=""; C_BLU=""; C_OFF=""; fi
ts()   { date '+%F %T'; }
info() { printf '%s %s[INFO]%s %s\n' "$(ts)" "$C_BLU" "$C_OFF" "$*"; }
ok()   { printf '%s %s[ OK ]%s %s\n' "$(ts)" "$C_GRN" "$C_OFF" "$*"; }
warn() { printf '%s %s[WARN]%s %s\n' "$(ts)" "$C_YEL" "$C_OFF" "$*" >&2; }
err()  { printf '%s %s[FAIL]%s %s\n' "$(ts)" "$C_RED" "$C_OFF" "$*" >&2; }
die()  { err "$*"; exit 1; }

on_error() {
  local rc=$? line=$1 cmd=$2
  err "unexpected error (exit ${rc}) at line ${line}: ${cmd}"
  [[ -n "$CURRENT_BACKUP" ]] && err "backup of the previous state: ${CURRENT_BACKUP} (restore: $0 rollback --from-backup ${CURRENT_BACKUP})"
  exit "$rc"
}
cleanup() { [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]] && rm -rf -- "$TMP_DIR"; return 0; }
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR
trap cleanup EXIT
trap 'err "interrupted"; exit 130' INT TERM

usage() {
  cat <<EOF
${PROJECT} ${VERSION}

Usage: sudo $0 <command> [options]

Commands:
  plan        show what would change; makes no changes
  install     install or update the integration (idempotent)
  test        run tests/cases.json through wazuh-logtest
  verify      check the current state; makes no changes
  rollback    remove the integration (managed block, decoder, rules)

Options:
  -c, --config FILE     config file (default: ${SCRIPT_DIR}/config.env)
      --adopt           take over a manually created KSC <remote> block / decoder / rules
      --no-restart      install files but do not restart ${DEFAULTS[SERVICE_NAME]}
      --from-backup DIR rollback: restore files from this backup instead of removing
  -y, --yes             do not ask for confirmation
  -h, --help            this help

Configuration keys (config file or environment variables; environment wins):
  ${CONFIG_KEYS}
EOF
}

# --------------------------------------------------------------- config ------
# Safe KEY=VALUE parser: the config file is never sourced/executed.
load_config() {
  local key value line n=0
  declare -gA CFG=()
  for key in $CONFIG_KEYS; do CFG[$key]="${DEFAULTS[$key]}"; done

  if [[ -f "$CONFIG_FILE" ]]; then
    local perm owner
    perm="$(stat -c '%a' -- "$CONFIG_FILE")"; owner="$(stat -c '%U' -- "$CONFIG_FILE")"
    [[ "$owner" == "root" ]] || die "config ${CONFIG_FILE} must be owned by root (is ${owner})"
    (( (8#$perm & 8#022) == 0 )) || die "config ${CONFIG_FILE} must not be group/world writable (mode ${perm})"
    while IFS= read -r line || [[ -n "$line" ]]; do
      n=$((n + 1))
      [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
      [[ "$line" =~ ^[[:space:]]*([A-Z_]+)=(.*)$ ]] || die "${CONFIG_FILE}:${n}: expected KEY=VALUE"
      key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
      value="${value%"${value##*[![:space:]]}"}"                       # rtrim
      if [[ "$value" =~ ^\"(.*)\"$ || "$value" =~ ^\'(.*)\'$ ]]; then value="${BASH_REMATCH[1]}"; fi
      [[ " $CONFIG_KEYS " == *" $key "* ]] || die "${CONFIG_FILE}:${n}: unknown key ${key}"
      CFG[$key]="$value"
    done < "$CONFIG_FILE"
  elif [[ "$CMD" != "test" ]]; then
    warn "config ${CONFIG_FILE} not found; using defaults and environment variables"
  fi
  for key in $CONFIG_KEYS; do
    if [[ -n "${!key:-}" ]]; then CFG[$key]="${!key}"; fi
  done
}

validate_config() {
  local key
  for key in KSC_IP LISTEN_IP; do
    [[ -n "${CFG[$key]}" ]] || die "${key} is required (set it in ${CONFIG_FILE}, see config.env.example)"
    "$PYTHON" -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1])' "${CFG[$key]}" 2>/dev/null \
      || die "${key}=${CFG[$key]} is not a valid IPv4 address"
  done
  if ! [[ "${CFG[SYSLOG_PORT]}" =~ ^[0-9]+$ ]] || (( CFG[SYSLOG_PORT] < 1 || CFG[SYSLOG_PORT] > 65535 )); then
    die "SYSLOG_PORT must be 1..65535"
  fi
  [[ "${CFG[SYSLOG_PROTOCOL]}" =~ ^(tcp|udp)$ ]] || die "SYSLOG_PROTOCOL must be tcp or udp"
  for key in BACKUP_KEEP RULE_ID_MIN RULE_ID_MAX AGENT_RECOVERY_TIMEOUT; do
    [[ "${CFG[$key]}" =~ ^[0-9]+$ ]] || die "${key} must be a number"
  done
  [[ "${CFG[BACKUP_ROOT]}" == /* ]] || die "BACKUP_ROOT must be an absolute path"
  if ! ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qxF -- "${CFG[LISTEN_IP]}"; then
    die "LISTEN_IP=${CFG[LISTEN_IP]} is not configured on this host (wazuh-remoted could not bind to it)"
  fi
}

# --------------------------------------------------------------- helpers -----
require_root() { [[ $EUID -eq 0 ]] || die "run as root (sudo $0 ${CMD})"; }

require_cmds() {
  local c
  for c in "$@"; do command -v "$c" >/dev/null 2>&1 || die "required command not found: ${c}"; done
}

pick_python() {
  if command -v python3 >/dev/null 2>&1; then PYTHON="$(command -v python3)"
  elif [[ -x "${CFG[OSSEC_DIR]:-/var/ossec}/framework/python/bin/python3" ]]; then PYTHON="${CFG[OSSEC_DIR]}/framework/python/bin/python3"
  else die "python3 not found (system python3 or Wazuh embedded python is required)"; fi
}

paths() {
  OSSEC_CONF="${CFG[OSSEC_DIR]}/etc/ossec.conf"
  DST_DECODER="${CFG[OSSEC_DIR]}/etc/decoders/kaspersky_ksc.xml"
  DST_RULES="${CFG[OSSEC_DIR]}/etc/rules/kaspersky_ksc_rules.xml"
  LOGTEST="${CFG[OSSEC_DIR]}/bin/wazuh-logtest"
  OSSEC_LOG="${CFG[OSSEC_DIR]}/logs/ossec.log"
}

confirm() {
  (( ASSUME_YES )) && return 0
  [[ -t 0 ]] || die "not a terminal: re-run with --yes to confirm non-interactively"
  local answer
  read -r -p "$1 [y/N] " answer
  [[ "$answer" =~ ^[YyДд]$ ]] || die "aborted by user"
}

acquire_lock() {
  exec 9>"/run/lock/${PROJECT}.lock"
  flock -n 9 || die "another ${PROJECT} run is in progress"
}

check_wazuh() {
  [[ -x "${CFG[OSSEC_DIR]}/bin/wazuh-control" ]] || die "Wazuh not found in ${CFG[OSSEC_DIR]}"
  [[ -f "$OSSEC_CONF" ]] || die "${OSSEC_CONF} not found"
  local type
  type="$(sed -n 's/^WAZUH_TYPE="\(.*\)"/\1/p' "${CFG[OSSEC_DIR]}/etc/ossec-init.conf" 2>/dev/null || true)"
  [[ -z "$type" ]] && type="$("${CFG[OSSEC_DIR]}/bin/wazuh-control" info -t 2>/dev/null || true)"
  [[ -z "$type" || "$type" == "server" ]] || die "this host is a Wazuh '${type}', not a manager"
  systemctl cat "${CFG[SERVICE_NAME]}" >/dev/null 2>&1 || die "systemd service ${CFG[SERVICE_NAME]} not found"
}

check_cluster() {
  local section disabled node_type
  section="$(sed -n '/<cluster>/,/<\/cluster>/p' "$OSSEC_CONF")"
  [[ -z "$section" ]] && return 0
  disabled="$(sed -n 's:.*<disabled>[[:space:]]*\(yes\|no\)[[:space:]]*</disabled>.*:\1:p' <<<"$section" | head -n1)"
  node_type="$(sed -n 's:.*<node_type>[[:space:]]*\([a-z]*\)[[:space:]]*</node_type>.*:\1:p' <<<"$section" | head -n1)"
  [[ "$disabled" == "yes" ]] && return 0
  [[ "$node_type" == "worker" ]] && die "cluster worker node: run this on the master (rules and decoders are synced from it)"
  warn "cluster is enabled (master): decoders and rules will be synced to workers, but the syslog <remote> block applies to this node only"
}

check_rule_ids() {
  local f id conflicts=()
  shopt -s nullglob
  for f in "${CFG[OSSEC_DIR]}"/etc/rules/*.xml; do
    [[ "$f" == "$DST_RULES" ]] && continue
    while read -r id; do
      if (( id >= CFG[RULE_ID_MIN] && id <= CFG[RULE_ID_MAX] )); then conflicts+=("${id} in ${f}"); fi
    done < <(grep -oE 'rule[[:space:]]+id="[0-9]+"' "$f" | grep -oE '[0-9]+' || true)
  done
  shopt -u nullglob
  (( ${#conflicts[@]} == 0 )) || die "rule IDs ${CFG[RULE_ID_MIN]}-${CFG[RULE_ID_MAX]} already used: ${conflicts[*]}"
  while read -r id; do
    (( id >= CFG[RULE_ID_MIN] && id <= CFG[RULE_ID_MAX] )) || die "repository rule ${id} is outside RULE_ID_MIN..RULE_ID_MAX"
  done < <(grep -oE 'rule[[:space:]]+id="[0-9]+"' "$REPO_RULES" | grep -oE '[0-9]+')
}

check_decoder_names() {
  local hits
  hits="$(grep -lE 'decoder[[:space:]]+name="kaspersky-ksc(-fields)?"' "${CFG[OSSEC_DIR]}"/etc/decoders/*.xml 2>/dev/null \
          | grep -vxF "$DST_DECODER" || true)"
  [[ -z "$hits" ]] || die "decoder name kaspersky-ksc is already defined in: ${hits//$'\n'/, }"
}

# state of a target file: absent | same | managed | unmanaged
file_state() {
  local src=$1 dst=$2
  if [[ ! -e "$dst" ]]; then echo absent
  elif cmp -s -- "$src" "$dst"; then echo same
  elif grep -qF -- "$MARKER" "$dst"; then echo managed
  else echo unmanaged; fi
}

active_agents() { "${CFG[OSSEC_DIR]}/bin/agent_control" -l 2>/dev/null | grep -c 'Active' || true; }

port_listening() {
  local flag=-ltnH
  [[ "${CFG[SYSLOG_PROTOCOL]}" == "udp" ]] && flag=-lunH
  ss "$flag" "sport = :${CFG[SYSLOG_PORT]}" 2>/dev/null | awk '{print $4}' | grep -qxF -- "${CFG[LISTEN_IP]}:${CFG[SYSLOG_PORT]}"
}

# --------------------------------------------------------------- plan --------
# Renders the desired state into $TMP_DIR and sets CHANGES.
build_plan() {
  TMP_DIR="$(mktemp -d)"
  local rc=0 adopt_flag=() state
  (( ADOPT )) && adopt_flag=(--adopt)
  "$PYTHON" "$HELPER" render --conf "$OSSEC_CONF" --port "${CFG[SYSLOG_PORT]}" --proto "${CFG[SYSLOG_PROTOCOL]}" \
      --ksc-ip "${CFG[KSC_IP]}" --listen-ip "${CFG[LISTEN_IP]}" "${adopt_flag[@]}" \
      --out "${TMP_DIR}/ossec.conf" 2>"${TMP_DIR}/render.err" || rc=$?
  if (( rc == 3 )); then
    cat "${TMP_DIR}/render.err" >&2
    die "an unmanaged <remote> already uses ${CFG[SYSLOG_PORT]}/${CFG[SYSLOG_PROTOCOL]} (e.g. configured manually). Check it above and re-run with --adopt to take it over"
  elif (( rc != 0 )); then
    cat "${TMP_DIR}/render.err" >&2; die "cannot render ${OSSEC_CONF}"
  fi
  if (( ADOPT )) && [[ -s "${TMP_DIR}/render.err" ]]; then cat "${TMP_DIR}/render.err" >&2; fi

  CHANGES=0
  printf '\n%s=== Plan ===%s\n' "$C_BLU" "$C_OFF"
  if cmp -s "$OSSEC_CONF" "${TMP_DIR}/ossec.conf"; then
    echo "ossec.conf:   no changes"
  else
    echo "ossec.conf:   will change"; CHANGES=$((CHANGES + 1))
    diff -u --label "${OSSEC_CONF} (current)" --label "${OSSEC_CONF} (new)" "$OSSEC_CONF" "${TMP_DIR}/ossec.conf" || true
  fi
  local pair src dst
  for pair in "${REPO_DECODER}|${DST_DECODER}" "${REPO_RULES}|${DST_RULES}"; do
    src="${pair%%|*}"; dst="${pair##*|}"
    state="$(file_state "$src" "$dst")"
    case "$state" in
      same)      echo "$(basename "$dst"): no changes" ;;
      absent)    echo "$(basename "$dst"): will be created"; CHANGES=$((CHANGES + 1)) ;;
      managed)   echo "$(basename "$dst"): will be updated"; CHANGES=$((CHANGES + 1))
                 diff -u --label "${dst} (current)" --label "${dst} (new)" "$dst" "$src" || true ;;
      unmanaged) if (( ADOPT )); then
                   echo "$(basename "$dst"): exists without '${MARKER}' marker — will be ADOPTED (overwritten, backup kept)"
                   diff -u --label "${dst} (current)" --label "${dst} (new)" "$dst" "$src" || true
                   CHANGES=$((CHANGES + 1))
                 else
                   die "${dst} exists and is not managed by ${PROJECT}. Re-run with --adopt to take it over"
                 fi ;;
    esac
  done
  printf '%s=== %d change(s) ===%s\n\n' "$C_BLU" "$CHANGES" "$C_OFF"
}

# --------------------------------------------------------------- backup ------
make_backup() {
  local dir f
  install -d -m 0700 -- "${CFG[BACKUP_ROOT]}"
  dir="$(mktemp -d "${CFG[BACKUP_ROOT]}/$(date +%Y%m%d-%H%M%S)-XXXX")"
  : > "${dir}/MANIFEST"
  for f in "$OSSEC_CONF" "$DST_DECODER" "$DST_RULES"; do
    if [[ -e "$f" ]]; then
      cp -a -- "$f" "${dir}/$(basename "$f")"
      printf 'present %s\n' "$f" >> "${dir}/MANIFEST"
    else
      printf 'absent %s\n' "$f" >> "${dir}/MANIFEST"
    fi
  done
  CURRENT_BACKUP="$dir"
  ok "backup: ${dir}"
  # keep only the newest BACKUP_KEEP backups
  find "${CFG[BACKUP_ROOT]}" -mindepth 1 -maxdepth 1 -type d -name '20*' -printf '%f\n' | sort -r \
    | tail -n "+$((CFG[BACKUP_KEEP] + 1))" | while read -r old; do rm -rf -- "${CFG[BACKUP_ROOT]:?}/${old}"; done
}

restore_backup() {
  local dir=$1 state path
  [[ -f "${dir}/MANIFEST" ]] || die "${dir} is not a ${PROJECT} backup (no MANIFEST)"
  while read -r state path; do
    case "$state" in
      present) cp -a -- "${dir}/$(basename "$path")" "$path" ;;
      absent)  rm -f -- "$path" ;;
    esac
  done < "${dir}/MANIFEST"
  warn "restored files from ${dir}"
}

# --------------------------------------------------------------- apply -------
install_atomic() {  # src dst owner:group mode
  local src=$1 dst=$2 owner=$3 mode=$4 tmp
  tmp="$(mktemp "$(dirname -- "$dst")/.$(basename -- "$dst").XXXXXX")"
  cat -- "$src" > "$tmp"
  chown "$owner" -- "$tmp"; chmod "$mode" -- "$tmp"
  mv -f -- "$tmp" "$dst"
}

apply_files() {
  local conf_owner conf_mode
  conf_owner="$(stat -c '%U:%G' -- "$OSSEC_CONF")"; conf_mode="$(stat -c '%a' -- "$OSSEC_CONF")"
  cmp -s "$OSSEC_CONF" "${TMP_DIR}/ossec.conf" || install_atomic "${TMP_DIR}/ossec.conf" "$OSSEC_CONF" "$conf_owner" "$conf_mode"
  cmp -s "$REPO_DECODER" "$DST_DECODER" 2>/dev/null || install_atomic "$REPO_DECODER" "$DST_DECODER" wazuh:wazuh 660
  cmp -s "$REPO_RULES" "$DST_RULES" 2>/dev/null || install_atomic "$REPO_RULES" "$DST_RULES" wazuh:wazuh 660
  ok "files installed"
}

daemon_supports_t() {  # daemons exit non-zero on -h, so do not pipe (pipefail)
  local help
  help="$("$1" -h 2>&1 || true)"
  grep -qE '^[[:space:]]*-t[[:space:]]' <<<"$help"
}

validate_installed() {
  local d
  for d in wazuh-analysisd wazuh-remoted; do
    local bin="${CFG[OSSEC_DIR]}/bin/${d}"
    if [[ -x "$bin" ]] && daemon_supports_t "$bin"; then
      if ! "$bin" -t >"${TMP_DIR}/${d}.t.log" 2>&1; then
        cat "${TMP_DIR}/${d}.t.log" >&2; return 1
      fi
      ok "${d} -t: configuration test passed"
    else
      warn "${d} -t not available; skipped"
    fi
  done
  run_tests
}

run_tests() {
  [[ -x "$LOGTEST" ]] || { err "${LOGTEST} not found"; return 1; }
  info "running tests/cases.json through wazuh-logtest"
  "$PYTHON" "$TEST_RUNNER" --logtest "$LOGTEST" --cases "${SCRIPT_DIR}/tests/cases.json"
}

restart_manager() {
  info "restarting ${CFG[SERVICE_NAME]} (agents reconnect automatically, usually within a minute)"
  systemctl restart "${CFG[SERVICE_NAME]}" 9>&- || return 1
  local waited=0
  while (( waited < 120 )); do
    if systemctl is-active --quiet "${CFG[SERVICE_NAME]}" && port_listening; then
      ok "${CFG[SERVICE_NAME]} active, ${CFG[LISTEN_IP]}:${CFG[SYSLOG_PORT]}/${CFG[SYSLOG_PROTOCOL]} listening"
      return 0
    fi
    sleep 2; waited=$((waited + 2))
  done
  err "${CFG[SERVICE_NAME]} not active or port ${CFG[SYSLOG_PORT]} not listening after 120s"
  return 1
}

# new ERROR/CRITICAL lines in ossec.log after byte offset $1. Scope-related ones fail, others warn.
check_log_since() {
  local offset=$1 lines scoped other
  lines="$(tail -c "+$((offset + 1))" "$OSSEC_LOG" 2>/dev/null | grep -E 'ERROR|CRITICAL' || true)"
  if [[ -n "${CFG[LOG_IGNORE_REGEX]}" ]]; then lines="$(grep -Ev -- "${CFG[LOG_IGNORE_REGEX]}" <<<"$lines" || true)"; fi
  [[ -z "$lines" ]] && { ok "no new errors in ossec.log"; return 0; }
  scoped="$(grep -Ei 'kaspersky|ksc|remoted|analysisd|decoder|rule|syslog|ossec\.conf' <<<"$lines" || true)"
  other="$(grep -Eiv 'kaspersky|ksc|remoted|analysisd|decoder|rule|syslog|ossec\.conf' <<<"$lines" || true)"
  [[ -n "$other" ]] && warn "unrelated errors in ossec.log (add to LOG_IGNORE_REGEX if expected):"$'\n'"$other"
  if [[ -n "$scoped" ]]; then err "errors related to the integration in ossec.log:"$'\n'"$scoped"; return 1; fi
  return 0
}

wait_agents() {
  local before=$1 now waited=0
  (( before == 0 )) && return 0
  while (( waited < CFG[AGENT_RECOVERY_TIMEOUT] )); do
    now="$(active_agents)"
    if (( now >= before )); then ok "agents active: ${now}/${before}"; return 0; fi
    sleep 10; waited=$((waited + 10))
  done
  warn "agents active: $(active_agents), before restart: ${before}. Some agents have not reconnected yet — check: ${CFG[OSSEC_DIR]}/bin/agent_control -l"
}

recover() {  # $1 reason, $2 restart|norestart. Restores the backup taken by this run.
  err "$1 — rolling back to ${CURRENT_BACKUP}"
  restore_backup "$CURRENT_BACKUP"
  if [[ "${2:-restart}" == restart ]] && (( ! NO_RESTART )); then
    systemctl restart "${CFG[SERVICE_NAME]}" 9>&- || true
    if systemctl is-active --quiet "${CFG[SERVICE_NAME]}"; then
      warn "previous state restored, ${CFG[SERVICE_NAME]} is active"
    else
      err "${CFG[SERVICE_NAME]} is NOT active after rollback: check ${OSSEC_LOG} immediately"
    fi
  fi
  exit 1
}

# --------------------------------------------------------------- commands ----
cmd_plan() { preflight; build_plan; }

cmd_install() {
  preflight
  build_plan
  if (( CHANGES == 0 )); then
    ok "already up to date"
    run_tests || die "tests failed on the current state"
    return 0
  fi
  confirm "Apply ${CHANGES} change(s)$( (( NO_RESTART )) || echo " and restart ${CFG[SERVICE_NAME]}")?"
  local agents_before log_offset
  agents_before="$(active_agents)"
  make_backup
  apply_files
  validate_installed || recover "validation failed (service was not restarted)" norestart
  if (( NO_RESTART )); then
    warn "--no-restart: changes take effect after 'systemctl restart ${CFG[SERVICE_NAME]}'"
    return 0
  fi
  log_offset="$(stat -c '%s' -- "$OSSEC_LOG" 2>/dev/null || echo 0)"
  restart_manager || recover "restart failed"
  sleep 5
  check_log_since "$log_offset" || recover "integration errors after restart"
  wait_agents "$agents_before"
  ok "installed. Backup of the previous state: ${CURRENT_BACKUP}"
}

cmd_test() {
  require_root
  load_config
  pick_python
  paths
  run_tests || die "tests failed"
  ok "all tests passed"
}

cmd_verify() {
  preflight
  local failed=0 state
  if systemctl is-active --quiet "${CFG[SERVICE_NAME]}"; then ok "${CFG[SERVICE_NAME]} active"
  else err "${CFG[SERVICE_NAME]} not active"; failed=1; fi
  TMP_DIR="$(mktemp -d)"
  if "$PYTHON" "$HELPER" render --conf "$OSSEC_CONF" --port "${CFG[SYSLOG_PORT]}" --proto "${CFG[SYSLOG_PROTOCOL]}" \
       --ksc-ip "${CFG[KSC_IP]}" --listen-ip "${CFG[LISTEN_IP]}" --out "${TMP_DIR}/ossec.conf" 2>/dev/null \
     && cmp -s "$OSSEC_CONF" "${TMP_DIR}/ossec.conf" && grep -qF "BEGIN ${PROJECT}" "$OSSEC_CONF"; then
    ok "ossec.conf: managed <remote> block present and up to date"
  else
    err "ossec.conf: managed <remote> block missing or differs from config (run: $0 plan)"; failed=1
  fi
  for state in "${REPO_DECODER}|${DST_DECODER}" "${REPO_RULES}|${DST_RULES}"; do
    if [[ "$(file_state "${state%%|*}" "${state##*|}")" == same ]]; then ok "$(basename "${state##*|}") matches repository"
    else err "$(basename "${state##*|}") missing or differs from repository"; failed=1; fi
  done
  if port_listening; then ok "listening on ${CFG[LISTEN_IP]}:${CFG[SYSLOG_PORT]}/${CFG[SYSLOG_PROTOCOL]}"
  else err "not listening on ${CFG[LISTEN_IP]}:${CFG[SYSLOG_PORT]}/${CFG[SYSLOG_PROTOCOL]}"; failed=1; fi
  info "active agents: $(active_agents)"
  local last
  last="$(grep -hF '"kaspersky"' "${CFG[OSSEC_DIR]}/logs/alerts/alerts.json" 2>/dev/null | tail -n1 \
          | "$PYTHON" -c 'import json,sys; d=sys.stdin.read().strip(); print(json.loads(d)["timestamp"] if d else "")' 2>/dev/null || true)"
  if [[ -n "$last" ]]; then info "last KSC alert in alerts.json: ${last}"
  else warn "no KSC alerts in the current alerts.json (normal if nothing was detected today; weekly EICAR test recommended)"; fi
  run_tests || failed=1
  (( failed == 0 )) || die "verify: some checks failed"
  ok "verify: all checks passed"
}

cmd_rollback() {
  preflight_basic
  TMP_DIR="$(mktemp -d)"
  if [[ -n "$FROM_BACKUP" ]]; then
    [[ -d "$FROM_BACKUP" ]] || die "backup directory not found: ${FROM_BACKUP}"
    echo "Will restore files listed in ${FROM_BACKUP}/MANIFEST:"; cat "${FROM_BACKUP}/MANIFEST"
    confirm "Restore this backup$( (( NO_RESTART )) || echo " and restart ${CFG[SERVICE_NAME]}")?"
    make_backup
    restore_backup "$FROM_BACKUP"
  else
    "$PYTHON" "$HELPER" remove --conf "$OSSEC_CONF" --out "${TMP_DIR}/ossec.conf"
    local f todo=()
    cmp -s "$OSSEC_CONF" "${TMP_DIR}/ossec.conf" || todo+=("remove managed <remote> block from ossec.conf")
    for f in "$DST_DECODER" "$DST_RULES"; do
      if [[ -e "$f" ]]; then
        grep -qF -- "$MARKER" "$f" || (( ADOPT )) || die "${f} is not managed by ${PROJECT}; re-run with --adopt to remove it anyway"
        todo+=("delete ${f}")
      fi
    done
    if (( ${#todo[@]} == 0 )); then ok "nothing to roll back"; return 0; fi
    diff -u --label "${OSSEC_CONF} (current)" --label "${OSSEC_CONF} (new)" "$OSSEC_CONF" "${TMP_DIR}/ossec.conf" || true
    printf ' - %s\n' "${todo[@]}"
    confirm "Roll back$( (( NO_RESTART )) || echo " and restart ${CFG[SERVICE_NAME]}")?"
    make_backup
    cmp -s "$OSSEC_CONF" "${TMP_DIR}/ossec.conf" || install_atomic "${TMP_DIR}/ossec.conf" "$OSSEC_CONF" \
      "$(stat -c '%U:%G' -- "$OSSEC_CONF")" "$(stat -c '%a' -- "$OSSEC_CONF")"
    rm -f -- "$DST_DECODER" "$DST_RULES"
  fi
  (( NO_RESTART )) && { warn "--no-restart: restart ${CFG[SERVICE_NAME]} to apply"; return 0; }
  systemctl restart "${CFG[SERVICE_NAME]}" 9>&-
  systemctl is-active --quiet "${CFG[SERVICE_NAME]}" || die "${CFG[SERVICE_NAME]} not active after rollback; restore with: $0 rollback --from-backup ${CURRENT_BACKUP}"
  ok "rolled back. Backup of the state before rollback: ${CURRENT_BACKUP}"
  [[ -z "$FROM_BACKUP" ]] && warn "KSC still exports events: disable 'Export events to SIEM' in the KSC Administration Server properties"
  return 0
}

preflight_basic() {
  require_root
  require_cmds systemctl ss ip awk sed grep cmp diff stat install flock mktemp
  load_config
  pick_python
  paths
  acquire_lock
  check_wazuh
}

preflight() {
  preflight_basic
  validate_config
  [[ -f "$REPO_DECODER" && -f "$REPO_RULES" && -f "$HELPER" && -f "$TEST_RUNNER" ]] || die "repository files missing; run from a full checkout"
  check_cluster
  check_rule_ids
  check_decoder_names
  ok "preflight passed (KSC ${CFG[KSC_IP]} -> ${CFG[LISTEN_IP]}:${CFG[SYSLOG_PORT]}/${CFG[SYSLOG_PROTOCOL]})"
}

# --------------------------------------------------------------- main --------
main() {
  [[ $# -gt 0 ]] || { usage; exit 1; }
  CMD=$1; shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c|--config)   [[ $# -ge 2 ]] || die "$1 needs a value"; CONFIG_FILE=$2; shift 2 ;;
      --adopt)       ADOPT=1; shift ;;
      --no-restart)  NO_RESTART=1; shift ;;
      --from-backup) [[ $# -ge 2 ]] || die "$1 needs a value"; FROM_BACKUP=$2; shift 2 ;;
      -y|--yes)      ASSUME_YES=1; shift ;;
      -h|--help)     usage; exit 0 ;;
      *)             die "unknown option: $1 (see --help)" ;;
    esac
  done
  case "$CMD" in
    plan)     cmd_plan ;;
    install)  cmd_install ;;
    test)     cmd_test ;;
    verify)   cmd_verify ;;
    rollback) cmd_rollback ;;
    -h|--help|help) usage ;;
    *)        usage; die "unknown command: ${CMD}" ;;
  esac
}

main "$@"
