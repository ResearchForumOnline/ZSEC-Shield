#!/bin/sh
set -eu

label=com.talktoai.zsec-antivirus-companion
install_root="$HOME/Library/Application Support/ZSEC Antivirus/Companion"
plist_path="$HOME/Library/LaunchAgents/$label.plist"
domain="gui/$(id -u)"

read_value() {
  value_file=$1
  [ -f "$value_file" ] && [ ! -L "$value_file" ] || return 1
  value=$(sed -n '1p' "$value_file")
  [ -n "$value" ] || return 1
  [ "$(wc -l < "$value_file" | tr -d ' ')" = "1" ] || return 1
  printf '%s\n' "$value"
}

if [ ! -d "$install_root" ] || [ -L "$install_root" ] || [ ! -f "$plist_path" ]; then
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

[ "$(stat -f '%u' "$install_root")" = "$(id -u)" ] ||
  add_reason "install directory belongs to another user"

cli=$(read_value "$install_root/cli.path" || true)
state_dir=$(read_value "$install_root/state.path" || true)
pinned_cli_hash=$(read_value "$install_root/cli.sha256" || true)
pinned_launcher_hash=$(read_value "$install_root/launcher.sha256" || true)
pinned_plist_hash=$(read_value "$install_root/plist.sha256" || true)

cli_hash_valid=false
launcher_hash_valid=false
plist_hash_valid=false
if [ -n "$cli" ] && [ -n "$pinned_cli_hash" ] && [ -f "$cli" ] && [ -x "$cli" ] && [ ! -L "$cli" ]; then
  if [ "$(/usr/bin/shasum -a 256 "$cli" | /usr/bin/awk '{print $1}')" = "$pinned_cli_hash" ]; then
    cli_hash_valid=true
  fi
fi
[ "$cli_hash_valid" = true ] || add_reason "CLI integrity check failed"

if [ -n "$pinned_launcher_hash" ] && [ -f "$install_root/run.sh" ] && [ ! -L "$install_root/run.sh" ]; then
  if [ "$(/usr/bin/shasum -a 256 "$install_root/run.sh" | /usr/bin/awk '{print $1}')" = "$pinned_launcher_hash" ]; then
    launcher_hash_valid=true
  fi
fi
[ "$launcher_hash_valid" = true ] || add_reason "launcher integrity check failed"

if [ -n "$pinned_plist_hash" ] && [ -f "$plist_path" ] && [ ! -L "$plist_path" ]; then
  if [ "$(/usr/bin/shasum -a 256 "$plist_path" | /usr/bin/awk '{print $1}')" = "$pinned_plist_hash" ]; then
    plist_hash_valid=true
  fi
fi
[ "$plist_hash_valid" = true ] || add_reason "LaunchAgent integrity check failed"

loaded=false
running=false
launch_state=absent
launch_output=$(launchctl print "$domain/$label" 2>/dev/null || true)
if [ -n "$launch_output" ]; then
  loaded=true
  launch_state=$(printf '%s\n' "$launch_output" | awk -F'= ' '/^[[:space:]]*state = / {print $2; exit}' | tr -d ' ')
  [ "$launch_state" = running ] && running=true
fi
[ "$loaded" = true ] || add_reason "LaunchAgent is not loaded"
[ "$running" = true ] || add_reason "LaunchAgent is not running"

health_fresh=false
health_age_seconds=-1
if [ -n "$state_dir" ] && [ -f "$state_dir/companion/health.json" ] && [ ! -L "$state_dir/companion/health.json" ]; then
  now=$(date +%s)
  modified=$(stat -f '%m' "$state_dir/companion/health.json")
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
  "launch_agent_loaded=$loaded" \
  "launch_agent_state=$launch_state" \
  "cli_hash_verified=$cli_hash_valid" \
  "launcher_hash_verified=$launcher_hash_valid" \
  "launch_agent_hash_verified=$plist_hash_valid" \
  "health_fresh=$health_fresh" \
  "health_age_seconds=$health_age_seconds" \
  "reasons=${reasons:-none}" \
  "primary_antivirus=false" \
  "pre_access_enforcement=false" \
  "existing_protection_unchanged=true"
exit "$exit_code"
