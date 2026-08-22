#!/bin/sh
set -eu

unit_name=zsec-antivirus-companion.service
install_root="$HOME/.local/share/zsec-antivirus/companion"
unit_path="$HOME/.config/systemd/user/$unit_name"

read_value() {
  value_file=$1
  [ -f "$value_file" ] && [ ! -L "$value_file" ] || return 1
  value=$(sed -n '1p' "$value_file")
  [ -n "$value" ] || return 1
  [ "$(wc -l < "$value_file" | tr -d ' ')" = "1" ] || return 1
  printf '%s\n' "$value"
}

if [ ! -d "$install_root" ] || [ -L "$install_root" ] || [ ! -f "$unit_path" ]; then
  printf '%s\n' \
    "installed=false" \
    "decision=not_installed" \
    "primary_antivirus=false" \
    "existing_protection_unchanged=true"
  exit 3
fi

reasons=
add_reason() {
  if [ -z "$reasons" ]; then reasons=$1; else reasons="$reasons; $1"; fi
}

[ "$(stat -c '%u' "$install_root")" = "$(id -u)" ] ||
  add_reason "install directory belongs to another user"

cli=$(read_value "$install_root/cli.path" || true)
state_dir=$(read_value "$install_root/state.path" || true)
pinned_cli_hash=$(read_value "$install_root/cli.sha256" || true)
pinned_launcher_hash=$(read_value "$install_root/launcher.sha256" || true)
pinned_unit_hash=$(read_value "$install_root/unit.sha256" || true)

cli_hash_valid=false
launcher_hash_valid=false
unit_hash_valid=false
if [ -n "$cli" ] && [ -n "$pinned_cli_hash" ] && [ -f "$cli" ] && [ -x "$cli" ] && [ ! -L "$cli" ]; then
  if [ "$(sha256sum "$cli" | awk '{print $1}')" = "$pinned_cli_hash" ]; then
    cli_hash_valid=true
  fi
fi
[ "$cli_hash_valid" = true ] || add_reason "CLI integrity check failed"

if [ -n "$pinned_launcher_hash" ] && [ -f "$install_root/run.sh" ] && [ ! -L "$install_root/run.sh" ]; then
  if [ "$(sha256sum "$install_root/run.sh" | awk '{print $1}')" = "$pinned_launcher_hash" ]; then
    launcher_hash_valid=true
  fi
fi
[ "$launcher_hash_valid" = true ] || add_reason "launcher integrity check failed"

if [ -n "$pinned_unit_hash" ] && [ -f "$unit_path" ] && [ ! -L "$unit_path" ]; then
  if [ "$(sha256sum "$unit_path" | awk '{print $1}')" = "$pinned_unit_hash" ]; then
    unit_hash_valid=true
  fi
fi
[ "$unit_hash_valid" = true ] || add_reason "systemd unit integrity check failed"

enabled=false
active=false
service_state=unavailable
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
  if systemctl --user is-enabled --quiet "$unit_name"; then enabled=true; fi
  if systemctl --user is-active --quiet "$unit_name"; then active=true; fi
  service_state=$(systemctl --user is-active "$unit_name" 2>/dev/null || true)
fi
[ "$enabled" = true ] || add_reason "systemd user service is not enabled"
[ "$active" = true ] || add_reason "systemd user service is not active"

health_fresh=false
health_age_seconds=-1
if [ -n "$state_dir" ] && [ -f "$state_dir/companion/health.json" ] && [ ! -L "$state_dir/companion/health.json" ]; then
  now=$(date +%s)
  modified=$(stat -c '%Y' "$state_dir/companion/health.json")
  health_age_seconds=$((now - modified))
  if [ "$health_age_seconds" -ge -5 ] && [ "$health_age_seconds" -le 105 ]; then
    health_fresh=true
  fi
fi
[ "$health_fresh" = true ] || add_reason "health heartbeat is absent, stale or from the future"

healthy=false
decision=degraded
exit_code=2
if [ -z "$reasons" ]; then
  healthy=true
  decision=healthy_companion
  exit_code=0
fi

printf '%s\n' \
  "installed=true" \
  "healthy=$healthy" \
  "decision=$decision" \
  "systemd_enabled=$enabled" \
  "systemd_active=$active" \
  "systemd_state=$service_state" \
  "cli_hash_verified=$cli_hash_valid" \
  "launcher_hash_verified=$launcher_hash_valid" \
  "unit_hash_verified=$unit_hash_valid" \
  "health_fresh=$health_fresh" \
  "health_age_seconds=$health_age_seconds" \
  "reasons=${reasons:-none}" \
  "primary_antivirus=false" \
  "pre_access_enforcement=false" \
  "existing_protection_unchanged=true"
exit "$exit_code"
