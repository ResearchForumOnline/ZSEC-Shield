#!/bin/sh
set -eu
umask 077

label=com.talktoai.zsec-antivirus-companion
script_dir=$(CDPATH= cd -P "$(dirname "$0")" && pwd)
template="$script_dir/$label.plist.template"
source_launcher="$script_dir/run.sh"
protected_root="$HOME/Downloads"
state_dir="$HOME/Library/Application Support/ZSEC Shield"
install_root="$HOME/Library/Application Support/ZSEC Antivirus/Companion"
launch_agents="$HOME/Library/LaunchAgents"
plist_path="$launch_agents/$label.plist"
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

Installs an unprivileged LaunchAgent for foreground post-change monitoring.
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

xml_escape() {
  printf '%s' "$1" | sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g' \
    -e "s/'/\\\&apos;/g"
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
[ -f "$template" ] && [ ! -L "$template" ] || fail "LaunchAgent template is missing"
[ -f "$source_launcher" ] && [ ! -L "$source_launcher" ] || fail "launcher is missing"

if [ -z "$cli" ]; then
  cli=$(command -v zsec-shield 2>/dev/null || true)
  [ -n "$cli" ] || cli=$(command -v zero-security 2>/dev/null || true)
fi
[ -n "$cli" ] || fail "cannot find zsec-shield or zero-security; pass --cli"
reject_control_characters "$cli"
reject_control_characters "$protected_root"
require_absolute_clean_path "$state_dir"
[ -x /usr/bin/shasum ] || fail "required macOS SHA-256 utility is unavailable: /usr/bin/shasum"
cli=$(canonical_file "$cli")
[ -x "$cli" ] || fail "CLI is not executable: $cli"
protected_root=$(canonical_directory "$protected_root")

case "$protected_root/" in "$state_dir/"*) fail "protected root is below the state directory" ;; esac
case "$state_dir/" in "$protected_root/"*) fail "state directory is below the protected root" ;; esac

[ ! -e "$install_root" ] && [ ! -L "$install_root" ] ||
  fail "companion install directory already exists; inspect or uninstall it first"
[ ! -e "$plist_path" ] && [ ! -L "$plist_path" ] ||
  fail "LaunchAgent already exists; refusing to overwrite it"

cli_hash=$(/usr/bin/shasum -a 256 "$cli" | /usr/bin/awk '{print $1}')
if [ "$plan" = true ]; then
  printf '%s\n' \
    "product=ZSEC Antivirus" \
    "mode=foreground-post-change-companion" \
    "cli=$cli" \
    "cli_sha256=$cli_hash" \
    "protected_root=$protected_root" \
    "backend=native" \
    "state_directory=$state_dir" \
    "launch_agent=$plist_path" \
    "primary_antivirus=false" \
    "pre_access_enforcement=false" \
    "existing_protection_unchanged=true" \
    "plan_only=true"
  exit 0
fi

command -v launchctl >/dev/null 2>&1 || fail "launchctl is unavailable"
command -v plutil >/dev/null 2>&1 || fail "plutil is unavailable"

domain="gui/$(id -u)"
state_preexisted=false
evidence_preexisted=false
launch_agents_preexisted=false
bootstrap_attempted=false
completed=false

rollback() {
  code=$?
  trap - EXIT HUP INT TERM
  if [ "$completed" != true ]; then
    if [ "$bootstrap_attempted" = true ]; then
      launchctl bootout "$domain" "$plist_path" >/dev/null 2>&1 || true
    fi
    rm -f "$plist_path" "$plist_path.tmp.$$"
    rm -f \
      "$install_root/run.sh" \
      "$install_root/cli.path" \
      "$install_root/protected-root.path" \
      "$install_root/state.path" \
      "$install_root/cli.sha256" \
      "$install_root/launcher.sha256" \
      "$install_root/plist.sha256" \
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
    if [ "$launch_agents_preexisted" = false ]; then
      rmdir "$launch_agents" 2>/dev/null || true
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
/usr/bin/install -m 0700 "$source_launcher" "$install_root/run.sh"
printf '%s\n' "$cli" > "$install_root/cli.path"
printf '%s\n' "$protected_root" > "$install_root/protected-root.path"
printf '%s\n' "$state_dir" > "$install_root/state.path"
printf '%s\n' "$cli_hash" > "$install_root/cli.sha256"
printf '%s\n' 'zsec.antivirus.macos-companion.v1' > "$install_root/schema.txt"
launcher_hash=$(/usr/bin/shasum -a 256 "$install_root/run.sh" | /usr/bin/awk '{print $1}')
printf '%s\n' "$launcher_hash" > "$install_root/launcher.sha256"

[ -e "$launch_agents" ] && launch_agents_preexisted=true
mkdir -p "$launch_agents"
[ -d "$launch_agents" ] && [ ! -L "$launch_agents" ] || fail "LaunchAgents directory is invalid"

launcher_xml=$(xml_escape "$install_root/run.sh")
config_xml=$(xml_escape "$install_root")
launcher_replacement=$(sed_replacement_escape "$launcher_xml")
config_replacement=$(sed_replacement_escape "$config_xml")
sed \
  -e "s|@@LAUNCHER@@|$launcher_replacement|g" \
  -e "s|@@CONFIG_DIR@@|$config_replacement|g" \
  "$template" > "$plist_path.tmp.$$"
plutil -lint "$plist_path.tmp.$$" >/dev/null
chmod 600 "$plist_path.tmp.$$"
mv "$plist_path.tmp.$$" "$plist_path"
plist_hash=$(/usr/bin/shasum -a 256 "$plist_path" | /usr/bin/awk '{print $1}')
printf '%s\n' "$plist_hash" > "$install_root/plist.sha256"

bootstrap_attempted=true
launchctl bootstrap "$domain" "$plist_path"
launchctl print "$domain/$label" >/dev/null

completed=true
trap - EXIT HUP INT TERM
printf '%s\n' \
  "installed=true" \
  "product=ZSEC Antivirus" \
  "launch_agent=$plist_path" \
  "protected_root=$protected_root" \
  "backend=native" \
  "state_preserved_on_uninstall=$state_dir" \
  "primary_antivirus=false" \
  "pre_access_enforcement=false" \
  "existing_protection_unchanged=true"
