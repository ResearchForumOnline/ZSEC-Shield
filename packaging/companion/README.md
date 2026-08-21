# ZSEC Antivirus user companion packages

These packages supervise the existing ZSEC Shield foreground watcher for one signed-in
desktop user. They do not install a privileged daemon, register a primary antivirus,
mediate file access or change another security product.

The installed command is equivalent to:

```text
zsec-shield --state-dir <state-directory> protect <Downloads> --backend native
```

Additional fixed arguments bound the event queue, file size, reconciliation interval,
health heartbeat and rotating event log. Quarantine is deliberately not enabled by
these packages. A user can stop and uninstall the companion without deleting feed,
health, event or quarantine state.

## Security boundary

- Monitoring starts after native filesystem events. It is not kernel pre-access
  enforcement, EDR, memory scanning or complete malware prevention.
- Microsoft Defender, Malwarebytes, XProtect, Gatekeeper, SIP, firewalls and Linux
  security controls stay active and unchanged.
- Installation is per-user and refuses root execution.
- The selected CLI is pinned by SHA-256. If that executable changes, the launcher
  fails closed until the user reviews and reinstalls the companion.
- Protected and configuration paths are passed as distinct quoted arguments. Config
  files are data-only one-line values and are never sourced or evaluated as shell code.
- Only one supervisor job is installed. ZSEC Shield's state lock provides a second
  single-instance boundary.
- Console output is sent to the null device. Operational evidence uses a compact
  health file and a 4 MiB event log with three retained rotations.

## macOS

Requirements: a normal interactive macOS user session, `launchctl`, `shasum`, an
existing Downloads directory and an executable `zsec-shield` or `zero-security` CLI.

```sh
cd packaging/companion/macos
sh ./install.sh --cli /absolute/path/to/zsec-shield
sh ./status.sh
sh ./uninstall.sh
```

The installer writes only:

- `~/Library/Application Support/ZSEC Antivirus/Companion/`
- `~/Library/LaunchAgents/com.talktoai.zsec-antivirus-companion.plist`
- the selected state directory, defaulting to
  `~/Library/Application Support/ZSEC Shield`

The LaunchAgent runs at user login, restarts only after failure and uses a 30-second
launchd throttle. It neither requests root nor changes XProtect, Gatekeeper, SIP,
firewall settings, privacy permissions, exclusions or login-wide security policy.

Use `./install.sh --plan` to inspect resolved paths without writing anything. The
installer rolls back its LaunchAgent and companion files if bootstrap or verification
fails. Uninstall verifies ownership and recorded hashes before removing only the
owned LaunchAgent and companion directory; state is preserved.

## Linux

Requirements: a desktop login with an available systemd user manager, `systemctl`,
`sha256sum`, an existing Downloads directory and an executable `zsec-shield` or
`zero-security` CLI.

```sh
cd packaging/companion/linux
sh ./install.sh --cli /absolute/path/to/zsec-shield
sh ./status.sh
sh ./uninstall.sh
```

The installer writes only:

- `~/.local/share/zsec-antivirus/companion/`
- `~/.config/systemd/user/zsec-antivirus-companion.service`
- the selected state directory, defaulting to `~/.local/state/zsec-shield`

The unit is enabled for the current user's login session. The installer does not
enable systemd lingering, so it does not extend the user's login lifetime. The unit
uses `Restart=on-failure`, a 30-second restart delay, a five-attempt/300-second start
limit, read-only home protection with a narrow state-directory write exception,
network denial and resource bounds. No firewall, package-manager, endpoint-agent,
antivirus-exclusion or system service changes are made.

Use `./install.sh --plan` for a non-mutating path and policy preview. Failed installs
disable and remove only the unit created by that attempt. Uninstall verifies the unit
and launcher hashes, stops the user service, removes only companion-owned files and
preserves the state directory. It remains reversible even when the external CLI was
updated or removed; status reports that integrity change separately.

## Status exit codes

Both status scripts use the same exit contract:

- `0`: installed, supervisor job active, pinned files valid and heartbeat fresh.
- `2`: installed but stopped, stale or integrity-degraded.
- `3`: no owned companion installation was found.

Status is local evidence, not a clean-system verdict or proof of detection efficacy.

## Focused validation

From the repository root:

```text
python packaging/companion/test_companion_packages.py -v
```

The test is non-mutating. It validates package structure, fixed protection arguments,
restart/backoff policies, service hardening, rollback markers, non-primary boundaries
and shell syntax when a compatible `sh` is available. Actual launchd and systemd-user
activation must be tested on disposable macOS and Linux accounts respectively.
