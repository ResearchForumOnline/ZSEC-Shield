#!/bin/sh
set -eu
umask 077

label=com.talktoai.zsec-antivirus-companion
install_root="$HOME/Library/Application Support/ZSEC Antivirus/Companion"
plist_path="$HOME/Library/LaunchAgents/$label.plist"
domain="gui/$(id -u)"
plan=false

fail() {
  printf '%s\n' "zsec-companion uninstall: $*" >&2
  exit 1
}

read_value() {
  value_file=$1
  [ -f "$value_file" ] && [ ! -L "$value_file" ] || fail "missing owned record: $value_file"
  value=$(sed -n '1p' "$value_file")
  [ -n "$value" ] || fail "empty owned record: $value_file"
  [ "$(wc -l < "$value_file" | tr -d ' ')" = "1" ] || fail "invalid owned record: $value_file"
  printf '%s\n' "$value"
}

case "${1:-}" in
  --plan) plan=true ;;
  --help|-h)
    printf '%s\n' 'Usage: sh ./uninstall.sh [--plan]'
    exit 0
    ;;
  '') ;;
  *) fail "unknown argument: $1" ;;
esac
[ "$#" -le 1 ] || fail "too many arguments"
[ "$(id -u)" -ne 0 ] || fail "refusing root operation"

if [ ! -e "$install_root" ] && [ ! -L "$install_root" ] && [ ! -e "$plist_path" ]; then
  printf '%s\n' 'removed=false' 'decision=not_installed' 'existing_protection_unchanged=true'
  exit 0
fi

[ -d "$install_root" ] && [ ! -L "$install_root" ] || fail "install root is absent or symbolic"
[ "$(stat -f '%u' "$install_root")" = "$(id -u)" ] || fail "install root belongs to another user"
[ "$(read_value "$install_root/schema.txt")" = 'zsec.antivirus.macos-companion.v1' ] ||
  fail "installation schema is not owned by this uninstaller"

state_dir=$(read_value "$install_root/state.path")
launcher_hash=$(read_value "$install_root/launcher.sha256")
plist_hash=$(read_value "$install_root/plist.sha256")

[ -f "$plist_path" ] && [ ! -L "$plist_path" ] || fail "owned LaunchAgent is absent or symbolic"
[ "$(/usr/bin/shasum -a 256 "$plist_path" | /usr/bin/awk '{print $1}')" = "$plist_hash" ] ||
  fail "LaunchAgent changed; refusing removal"
[ -f "$install_root/run.sh" ] && [ ! -L "$install_root/run.sh" ] || fail "launcher is absent"
[ "$(/usr/bin/shasum -a 256 "$install_root/run.sh" | /usr/bin/awk '{print $1}')" = "$launcher_hash" ] ||
  fail "launcher changed; refusing removal"
if [ "$plan" = true ]; then
  printf '%s\n' \
    "remove_launch_agent=$plist_path" \
    "remove_companion_directory=$install_root" \
    "preserve_state_directory=$state_dir" \
    "existing_protection_unchanged=true" \
    "plan_only=true"
  exit 0
fi

launchctl bootout "$domain" "$plist_path" >/dev/null 2>&1 || true
if launchctl print "$domain/$label" >/dev/null 2>&1; then
  fail "LaunchAgent did not stop; refusing to remove files"
fi

rm -f "$plist_path"
rm -f \
  "$install_root/run.sh" \
  "$install_root/cli.path" \
  "$install_root/protected-root.path" \
  "$install_root/state.path" \
  "$install_root/cli.sha256" \
  "$install_root/launcher.sha256" \
  "$install_root/plist.sha256" \
  "$install_root/schema.txt"
rmdir "$install_root" || fail "companion directory contains unowned files; preserved for review"
rmdir "$(dirname "$install_root")" 2>/dev/null || true

printf '%s\n' \
  "removed=true" \
  "launch_agent_removed=true" \
  "companion_files_removed=true" \
  "preserved_state_directory=$state_dir" \
  "primary_antivirus=false" \
  "pre_access_enforcement=false" \
  "existing_protection_unchanged=true"
