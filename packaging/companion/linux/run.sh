#!/bin/sh
set -eu
umask 077

fail() {
  printf '%s\n' "zsec-companion: $*" >&2
  exit 1
}

reject_control_characters() {
  value=$1
  if LC_ALL=C printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    fail "a configured path contains control characters"
  fi
}

read_value() {
  value_file=$1
  [ -f "$value_file" ] && [ ! -L "$value_file" ] ||
    fail "missing regular configuration file: $value_file"
  value=$(sed -n '1p' "$value_file")
  [ -n "$value" ] || fail "empty configuration value: $value_file"
  [ "$(wc -l < "$value_file" | tr -d ' ')" = "1" ] ||
    fail "configuration values must contain exactly one line"
  reject_control_characters "$value"
  printf '%s\n' "$value"
}

[ "$#" -eq 1 ] || fail "expected the installed configuration directory"
config_dir=$1
reject_control_characters "$config_dir"
[ -d "$config_dir" ] && [ ! -L "$config_dir" ] ||
  fail "configuration directory is absent or symbolic"
[ "$(stat -c '%u' "$config_dir")" = "$(id -u)" ] ||
  fail "configuration directory belongs to another user"

cli=$(read_value "$config_dir/cli.path")
protected_root=$(read_value "$config_dir/protected-root.path")
state_dir=$(read_value "$config_dir/state.path")
pinned_cli_hash=$(read_value "$config_dir/cli.sha256")

[ -f "$cli" ] && [ -x "$cli" ] && [ ! -L "$cli" ] ||
  fail "the pinned ZSEC Shield CLI is absent, non-executable or symbolic"
[ -d "$protected_root" ] && [ ! -L "$protected_root" ] ||
  fail "the protected root is absent or symbolic"
[ -d "$state_dir" ] && [ ! -L "$state_dir" ] ||
  fail "the state directory is absent or symbolic"
[ "$(stat -c '%u' "$state_dir")" = "$(id -u)" ] ||
  fail "the state directory belongs to another user"

actual_cli_hash=$(sha256sum "$cli" | awk '{print $1}')
[ "$actual_cli_hash" = "$pinned_cli_hash" ] ||
  fail "the pinned CLI changed; review it and reinstall the companion"

evidence_dir="$state_dir/companion"
[ -d "$evidence_dir" ] && [ ! -L "$evidence_dir" ] ||
  fail "the bounded evidence directory is absent or symbolic"

exec "$cli" \
  --state-dir "$state_dir" \
  protect "$protected_root" \
  --backend native \
  --debounce-seconds 0.75 \
  --poll-seconds 1 \
  --reconcile-seconds 300 \
  --event-queue-size 2048 \
  --heartbeat-seconds 30 \
  --max-file-bytes 67108864 \
  --chunk-bytes 1048576 \
  --health-file "$evidence_dir/health.json" \
  --event-log "$evidence_dir/events.ndjson" \
  --event-log-max-bytes 4194304 \
  --event-log-backups 3 \
  --quiet
