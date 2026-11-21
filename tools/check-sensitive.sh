#!/usr/bin/env bash
# Scan repository files for data that must never be published:
#   - private IPv4 addresses (RFC 1918)
#   - tokens / private keys (GitHub, Telegram bot, PEM keys)
#   - organisation-specific strings from a LOCAL denylist (never committed)
#
#   tools/check-sensitive.sh            # all tracked + untracked (not ignored) files
#   tools/check-sensitive.sh --staged   # staged content only (used by .githooks/pre-commit)
#
# Denylist: one fixed string per line (case-insensitive, '#' comments), taken from
#   $SENSITIVE_DENYLIST, or .sensitive-denylist in the repository root (git-ignored).
# Only "file:line: category" is printed, never the matched value, so CI logs stay clean.
set -Eeuo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "error: not a git repository" >&2; exit 2; }
cd "$ROOT"
MODE="all"
[[ "${1:-}" == "--staged" ]] && MODE="staged"
DENYLIST="${SENSITIVE_DENYLIST:-${ROOT}/.sensitive-denylist}"

PRIVATE_IP='(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})([^0-9.]|$)'
SECRETS='(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,}|[0-9]{8,10}:AA[A-Za-z0-9_-]{33}|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----)'
SELF="tools/check-sensitive.sh"

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
deny_patterns="${TMP}/deny"
: > "$deny_patterns"
if [[ -f "$DENYLIST" ]]; then
  grep -vE '^[[:space:]]*(#|$)' "$DENYLIST" | sed 's/[[:space:]]*$//' > "$deny_patterns" || true
fi

list_files() {
  if [[ "$MODE" == "staged" ]]; then git diff --cached --name-only --diff-filter=ACMR -z
  else git ls-files -z --cached --others --exclude-standard; fi
}

content() {  # print the version of the file being checked
  if [[ "$MODE" == "staged" ]]; then git show ":$1" 2>/dev/null; else cat -- "$1"; fi
}

found=0
report() { printf '%s:%s: %s\n' "$1" "$2" "$3"; found=1; }

while IFS= read -r -d '' f; do
  [[ -f "$f" || "$MODE" == "staged" ]] || continue
  [[ "$f" == ".sensitive-denylist" ]] && { report "$f" 0 "denylist file must not be committed"; continue; }
  content "$f" > "${TMP}/file" || continue
  grep -Iq . "${TMP}/file" 2>/dev/null || continue            # skip binary / empty
  if [[ "$f" != "$SELF" ]]; then
    while IFS=: read -r n _; do report "$f" "$n" "private IPv4 address (RFC 1918)"; done \
      < <(grep -nE "$PRIVATE_IP" "${TMP}/file" || true)
    while IFS=: read -r n _; do report "$f" "$n" "token or private key"; done \
      < <(grep -nE "$SECRETS" "${TMP}/file" || true)
  fi
  if [[ -s "$deny_patterns" ]]; then
    while IFS=: read -r n _; do report "$f" "$n" "denylisted string"; done \
      < <(grep -niF -f "$deny_patterns" "${TMP}/file" || true)
  fi
done < <(list_files)

if (( found )); then
  echo "check-sensitive: FAILED — remove or anonymise the values above (use 192.0.2.0/24, example.local, PC-TEST01, testuser)" >&2
  exit 1
fi
if [[ -s "$deny_patterns" ]]; then
  echo "check-sensitive: OK ($(wc -l < "$deny_patterns") denylist entries, mode: ${MODE})"
else
  echo "check-sensitive: OK (mode: ${MODE}; no local denylist — only generic checks were done)"
fi
