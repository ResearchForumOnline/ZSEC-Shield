#!/bin/sh
set -eu
umask 077

unit_name=zsec-antivirus-companion.service
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
template="$script_dir/$unit_name.template"
source_launcher="$script_dir/run.sh"
protected_root="$HOME/Downloads"
state_dir="$HOME/.local/state/zsec-shield"
install_root="$HOME/.local/share/zsec-antivirus/companion"
user_unit_dir="$HOME/.config/systemd/user"
unit_path="$user_unit_dir/$unit_name"
cli=
plan=false

fail() {
  printf '%s\n' "zsec-companion install: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: sh ./install.sh [--cli ABSOLUTE_PATH] [--protected-root ABSOLUTE_DIRECTORY]
                       [--state-dir ABSOLUTE_DIRECTORY] [--plan]

Installs a hardened systemd --user service for foreground post-change monitoring.
It does not replace, disable, reconfigure or add exclusions to existing protection.
EOF
}

reject_control_characters() {
  value=$1
  if LC_ALL=C printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    fail "a path contains control characters"
  fi
}

canonical_file() {
  candidate=$1
  [ -f "$candidate" ] && [ ! -L "$candidate" ] ||
    fail "expected a regular, non-symbolic file: $candidate"
  directory=$(CDPATH= cd -P "$(dirname "$candidate")" && pwd)
  printf '%s/%s\n' "$directory" "$(basename "$candidate")"
}

canonical_directory() {
  candidate=$1
  [ -d "$candidate" ] && [ ! -L "$candidate" ] ||
    fail "expected a regular, non-symbolic directory: $candidate"
  (CDPATH= cd -P "$candidate" && pwd)
}

require_absolute_clean_path() {
  candidate=$1
  reject_control_characters "$candidate"
  case "$candidate" in
    /*) ;;
    *) fail "path must be absolute: $candidate" ;;
  esac
  case "/$candidate/" in
    */../*|*/./*) fail "path must not contain dot traversal components: $candidate" ;;
  esac
}

systemd_escape() {
  printf '%s' "$1" | sed \
    -e 's/\\/\\\\/g' \
    -e 's/"/\\"/g' \
    -e 's/%/%%/g'
}

sed_replacement_escape() {
  printf '%s' "$1" | sed 's/[\\&|]/\\&/g'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --cli)
      [ "$#" -ge 2 ] || fail "--cli requires a value"
      cli=$2
      shift 2
      ;;
    --protected-root)
      [ "$#" -ge 2 ] || fail "--protected-root requires a value"
      protected_root=$2
      shift 2
      ;;
    --state-dir)
      [ "$#" -ge 2 ] || fail "--state-dir requires a value"
      state_dir=$2
      shift 2
      ;;
    --plan)
      plan=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[ "$(id -u)" -ne 0 ] || fail "refusing root installation; use a normal desktop user"
[ -f "$template" ] && [ ! -L "$template" ] || fail "systemd unit template is missing"
[ -f "$source_launcher" ] && [ ! -L "$source_launcher" ] || fail "launcher is missing"

if [ -z "$cli" ]; then
  cli=$(command -v zsec-shield 2>/dev/null || true)
  [ -n "$cli" ] || cli=$(command -v zero-security 2>/dev/null || true)
fi
[ -n "$cli" ] || fail "cannot find zsec-shield or zero-security; pass --cli"
reject_control_characters "$cli"
reject_control_characters "$protected_root"
require_absolute_clean_path "$state_dir"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is unavailable"
cli=$(canonical_file "$cli")
[ -x "$cli" ] || fail "CLI is not executable: $cli"
protected_root=$(canonical_directory "$protected_root")

case "$protected_root/" in "$state_dir/"*) fail "protected root is below the state directory" ;; esac
case "$state_dir/" in "$protected_root/"*) fail "state directory is below the protected root" ;; esac

[ ! -e "$install_root" ] && [ ! -L "$install_root" ] ||
  fail "companion install directory already exists; inspect or uninstall it first"
[ ! -e "$unit_path" ] && [ ! -L "$unit_path" ] ||
  fail "systemd user unit already exists; refusing to overwrite it"

cli_hash=$(sha256sum "$cli" | awk '{print $1}')
if [ "$plan" = true ]; then
  printf '%s\n' \
    "product=ZSEC Antivirus" \
    "mode=foreground-post-change-companion" \
    "cli=$cli" \
    "cli_sha256=$cli_hash" \
    "protected_root=$protected_root" \
    "backend=native" \
    "state_directory=$state_dir" \
    "systemd_user_unit=$unit_path" \
    "primary_antivirus=false" \
    "pre_access_enforcement=false" \
    "existing_protection_unchanged=true" \
    "plan_only=true"
  exit 0
fi

command -v systemctl >/dev/null 2>&1 || fail "systemctl is unavailable"
systemctl --user show-environment >/dev/null 2>&1 ||
  fail "no usable systemd user manager is available in this login session"

state_preexisted=false
evidence_preexisted=false
unit_dir_preexisted=false
service_enable_attempted=false
completed=false

rollback() {
  code=$?
  trap - EXIT HUP INT TERM
  if [ "$completed" != true ]; then
    if [ "$service_enable_attempted" = true ]; then
      systemctl --user disable --now "$unit_name" >/dev/null 2>&1 || true
    fi
    rm -f "$unit_path" "$unit_path.tmp.$$"
    systemctl --user daemon-reload >/dev/null 2>&1 || true
    rm -f \
      "$install_root/run.sh" \
      "$install_root/cli.path" \
      "$install_root/protected-root.path" \
      "$install_root/state.path" \
      "$install_root/cli.sha256" \
      "$install_root/launcher.sha256" \
      "$install_root/unit.sha256" \
      "$install_root/schema.txt"
    rmdir "$install_root" 2>/dev/null || true
    rmdir "$(dirname "$install_root")" 2>/dev/null || true
    if [ "$evidence_preexisted" = false ]; then
      rm -f \
        "$state_dir/companion/health.json" \
        "$state_dir/companion/events.ndjson" \
        "$state_dir/companion/events.ndjson.1" \
        "$state_dir/companion/events.ndjson.2" \
        "$state_dir/companion/events.ndjson.3"
      rmdir "$state_dir/companion" 2>/dev/null || true
    fi
    if [ "$state_preexisted" = false ]; then
      rmdir "$state_dir" 2>/dev/null || true
    fi
    if [ "$unit_dir_preexisted" = false ]; then
      rmdir "$user_unit_dir" 2>/dev/null || true
    fi
  fi
  exit "$code"
}
trap rollback EXIT HUP INT TERM

[ -e "$state_dir" ] && state_preexisted=true
mkdir -p "$state_dir"
[ -d "$state_dir" ] && [ ! -L "$state_dir" ] || fail "state directory is symbolic or invalid"
chmod 700 "$state_dir"
state_dir=$(canonical_directory "$state_dir")
case "$protected_root/" in "$state_dir/"*) fail "protected root is below the resolved state directory" ;; esac
case "$state_dir/" in "$protected_root/"*) fail "resolved state directory is below the protected root" ;; esac

[ -e "$state_dir/companion" ] && evidence_preexisted=true
mkdir "$state_dir/companion" 2>/dev/null || {
  [ -d "$state_dir/companion" ] && [ ! -L "$state_dir/companion" ] ||
    fail "bounded evidence directory is invalid"
}
chmod 700 "$state_dir/companion"

mkdir -p "$(dirname "$install_root")"
mkdir "$install_root"
chmod 700 "$install_root"
install -m 0700 "$source_launcher" "$install_root/run.sh"
printf '%s\n' "$cli" > "$install_root/cli.path"
printf '%s\n' "$protected_root" > "$install_root/protected-root.path"
printf '%s\n' "$state_dir" > "$install_root/state.path"
printf '%s\n' "$cli_hash" > "$install_root/cli.sha256"
printf '%s\n' 'zsec.antivirus.linux-companion.v1' > "$install_root/schema.txt"
launcher_hash=$(sha256sum "$install_root/run.sh" | awk '{print $1}')
printf '%s\n' "$launcher_hash" > "$install_root/launcher.sha256"

[ -e "$user_unit_dir" ] && unit_dir_preexisted=true
mkdir -p "$user_unit_dir"
[ -d "$user_unit_dir" ] && [ ! -L "$user_unit_dir" ] || fail "systemd user-unit directory is invalid"

launcher_value=$(sed_replacement_escape "$(systemd_escape "$install_root/run.sh")")
config_value=$(sed_replacement_escape "$(systemd_escape "$install_root")")
state_value=$(sed_replacement_escape "$(systemd_escape "$state_dir")")
sed \
  -e "s|@@LAUNCHER@@|$launcher_value|g" \
  -e "s|@@CONFIG_DIR@@|$config_value|g" \
  -e "s|@@STATE_DIR@@|$state_value|g" \
  "$template" > "$unit_path.tmp.$$"
chmod 600 "$unit_path.tmp.$$"
mv "$unit_path.tmp.$$" "$unit_path"
unit_hash=$(sha256sum "$unit_path" | awk '{print $1}')
printf '%s\n' "$unit_hash" > "$install_root/unit.sha256"

if command -v systemd-analyze >/dev/null 2>&1; then
  systemd-analyze --user verify "$unit_path" >/dev/null
fi
systemctl --user daemon-reload
service_enable_attempted=true
systemctl --user enable --now "$unit_name"
systemctl --user is-enabled --quiet "$unit_name"
systemctl --user is-active --quiet "$unit_name"

completed=true
trap - EXIT HUP INT TERM
printf '%s\n' \
  "installed=true" \
  "product=ZSEC Antivirus" \
  "systemd_user_unit=$unit_path" \
  "protected_root=$protected_root" \
  "backend=native" \
  "state_preserved_on_uninstall=$state_dir" \
  "primary_antivirus=false" \
  "pre_access_enforcement=false" \
  "existing_protection_unchanged=true"
