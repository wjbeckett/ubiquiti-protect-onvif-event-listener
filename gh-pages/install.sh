#!/bin/sh
# install.sh — one-line installer for onvif-recorder.
#
#   curl -fsSL https://danielwoz.github.io/ubiquiti-protect-onvif-event-listener/install.sh | sh
#
# Detects the user's UniFi Protect release channel (Stable / Release Candidate
# / Early Access) and configures APT to pull matching onvif-recorder builds.
# Safe to re-run; it just (re)writes the keyring + sources list.
set -e

REPO_URL="https://danielwoz.github.io/ubiquiti-protect-onvif-event-listener"
KEYRING=/usr/share/keyrings/onvif-recorder-archive-keyring.gpg
SRC_FILE=/etc/apt/sources.list.d/onvif-recorder.list
CHANNEL_FILE=/etc/onvif-recorder/channel

if [ "$(id -u)" -ne 0 ]; then
    echo "This installer must run as root." >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get not found — this installer only supports Debian-based UniFi OS." >&2
    exit 1
fi

DEB_ARCH=$(dpkg --print-architecture)
case "$DEB_ARCH" in
    arm64) ;;
    *)
        echo "Unsupported architecture: $DEB_ARCH (only arm64 is published)." >&2
        exit 1
        ;;
esac

# Return 0 iff $REPO_URL/dists/$1/Release exists (HTTP 200).
suite_exists() {
    curl -fsI -o /dev/null "$REPO_URL/dists/$1/Release" 2>/dev/null
}

# Pick the first suite in the preference list that actually has a published
# Release file.  Falls back gracefully when a channel hasn't been cut yet
# (the common failure mode is `stable` missing because a release is still
# in `rc` or `early-access`).
select_available_suite() {
    for candidate in "$@"; do
        if suite_exists "$candidate"; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

# 1. GPG keyring.
echo "==> Fetching signing key ..."
mkdir -p /usr/share/keyrings
curl -fsSL "$REPO_URL/onvif-recorder.gpg" -o /tmp/onvif-recorder.gpg
gpg --dearmor < /tmp/onvif-recorder.gpg > "$KEYRING"
chmod 0644 "$KEYRING"
rm -f /tmp/onvif-recorder.gpg

# 2. Channel detection.
# Priority order for the default install:
#   preferred (existing channel file, if set and valid) -> stable -> rc -> early-access.
# If a suite's Release file isn't published yet, drop through to the next one
# rather than writing a dead channel that'd 404 on apt-get update.
mkdir -p /etc/onvif-recorder
PREFERRED=""
if [ -f "$CHANNEL_FILE" ]; then
    PREFERRED=$(tr -d '[:space:]' < "$CHANNEL_FILE")
fi
case "$PREFERRED" in
    stable|rc|early-access) ;;
    *) PREFERRED="" ;;
esac

if [ -n "$PREFERRED" ]; then
    CHANNEL=$(select_available_suite "$PREFERRED" stable rc early-access) || CHANNEL=""
else
    CHANNEL=$(select_available_suite stable rc early-access) || CHANNEL=""
fi

if [ -z "$CHANNEL" ]; then
    echo "No published apt suite reachable at $REPO_URL (stable/rc/early-access all 404)." >&2
    echo "Check your network or wait for the next release to be promoted." >&2
    exit 1
fi

if [ -n "$PREFERRED" ] && [ "$CHANNEL" != "$PREFERRED" ]; then
    echo "==> Preferred channel '$PREFERRED' not yet published; using '$CHANNEL'"
fi

echo "$CHANNEL" > "$CHANNEL_FILE"
echo "==> Using channel: $CHANNEL"

# 3. APT source.
echo "deb [arch=$DEB_ARCH signed-by=$KEYRING] $REPO_URL $CHANNEL main" \
    > "$SRC_FILE"

# 4. Install.
echo "==> apt-get update ..."
apt-get update \
    -o Dir::Etc::sourcelist="$SRC_FILE" \
    -o Dir::Etc::sourceparts=- \
    -o APT::Get::List-Cleanup=0

echo "==> Installing onvif-recorder ..."
apt-get install -y onvif-recorder

# 5. Persistent recovery layer (survives firmware upgrades + apt purge).
#
# UDM firmware upgrades wipe /usr/bin/onvif-recorder, the systemd unit, and
# /etc/apt/sources.list.d/ but preserve /data/ and /etc/cron.d/.  We install
# a small recovery layer on /data/onvif-recorder/ plus an @reboot trigger
# in /etc/cron.d/ so that on the next boot after a firmware upgrade we can:
#   (a) restore the config from the backup tarball in /data/, and
#   (b) re-run this install script to bring the package back.
#
# These files are intentionally NOT in the .deb package: they must survive
# `apt purge`, because purge wipes /etc/onvif-recorder/ and the apt source
# along with everything else dpkg knows about.  To remove the recovery
# layer too, see CLAUDE.md "Uninstall — full purge".
DATA_DIR=/data/onvif-recorder
echo "==> Installing recovery layer to $DATA_DIR ..."
mkdir -p "$DATA_DIR/backups"

# Self-copy install.sh so boot-restore can call it after a firmware wipe.
# Prefer the currently-running script (so a `sh /path/to/install.sh` run
# pushes that exact version onto /data — matters when iterating on the
# installer before publishing). Fall back to the URL when invoked via
# `curl | sh`, where $0 is /dev/stdin or similar.
if [ -f "$0" ] && [ -r "$0" ]; then
    cp "$0" "$DATA_DIR/install.sh"
else
    curl -fsSL "$REPO_URL/install.sh" -o "$DATA_DIR/install.sh"
fi
chmod 0755 "$DATA_DIR/install.sh"

cat > "$DATA_DIR/boot-restore.sh" <<'EOF_BOOT_RESTORE'
#!/bin/sh
# Auto-reinstall onvif-recorder after a firmware wipe.
# Triggered by /etc/cron.d/onvif-recorder-boot-restore @reboot.
exec >> /var/log/onvif-recorder-boot-restore.log 2>&1
echo "=== $(date -Is) boot-restore start ==="

# Wait for the system to settle (network, systemd, apt locks).
sleep 60

# Normal boot: package is already installed, nothing to do.
if dpkg -s onvif-recorder >/dev/null 2>&1; then
    echo "package already installed; nothing to do"
    exit 0
fi

# Restore the most recent config backup before reinstalling so the new
# package start-up sees the user's last channel / admin settings / cached
# protect-user-id.
BACKUP=/data/onvif-recorder/backups/config-current.tar.gz
if [ -f "$BACKUP" ]; then
    echo "restoring config from $BACKUP"
    tar -xzf "$BACKUP" -C /
fi

# Auto-reinstall is gated on a consent file written by install.sh.  The
# file is regenerated from /etc/onvif-recorder/config.json on every
# install/upgrade so flipping autoupdate_enabled in the admin UI takes
# effect on the *next* firmware wipe.
consent=$(cat /data/onvif-recorder/.autoupdate-consent 2>/dev/null)
if [ "$consent" != "true" ]; then
    echo "auto-reinstall consent not granted (.autoupdate-consent != true)"
    echo "to enable: echo true > /data/onvif-recorder/.autoupdate-consent"
    exit 0
fi

echo "running /data/onvif-recorder/install.sh"
sh /data/onvif-recorder/install.sh
echo "=== $(date -Is) boot-restore done ==="
EOF_BOOT_RESTORE
chmod 0755 "$DATA_DIR/boot-restore.sh"

cat > "$DATA_DIR/backup.sh" <<'EOF_BACKUP'
#!/bin/sh
# Snapshot onvif-recorder configuration to /data so it can be restored
# after a firmware wipe / apt purge.  Run by:
#   - install.sh, once at first install / upgrade
#   - /etc/cron.d/onvif-recorder-backup, daily
set -e
BACKUP_DIR=/data/onvif-recorder/backups
mkdir -p "$BACKUP_DIR"

# Build a tarball atomically — write to .tmp, mv into place.
tmp="$BACKUP_DIR/.config-current.tar.gz.tmp"
paths="etc/onvif-recorder"
[ -f /etc/default/onvif-recorder ]       && paths="$paths etc/default/onvif-recorder"
[ -f /etc/default/onvif-recorder.local ] && paths="$paths etc/default/onvif-recorder.local"
[ -d /var/lib/onvif-recorder ]           && paths="$paths var/lib/onvif-recorder"
# shellcheck disable=SC2086
tar -czf "$tmp" -C / $paths 2>/dev/null
mv -f "$tmp" "$BACKUP_DIR/config-current.tar.gz"

# Keep one dated snapshot per week (Sundays), prune to the last 4.
if [ "$(date +%w)" = "0" ]; then
    cp "$BACKUP_DIR/config-current.tar.gz" \
       "$BACKUP_DIR/config-$(date +%Y-%m-%d).tar.gz"
fi
ls -1t "$BACKUP_DIR"/config-2[0-9]*.tar.gz 2>/dev/null \
    | tail -n +5 | xargs -r rm -f

size=$(stat -c %s "$BACKUP_DIR/config-current.tar.gz")
echo "$(date -Is) backup written: $BACKUP_DIR/config-current.tar.gz ($size bytes)"
EOF_BACKUP
chmod 0755 "$DATA_DIR/backup.sh"

# Take an immediate backup so /data is current right after install.
"$DATA_DIR/backup.sh"

# Cron entries — these live in /etc/cron.d/ (which survives firmware
# upgrades on UDM) and are intentionally outside the .deb so that
# `apt purge` does not remove them.
cat > /etc/cron.d/onvif-recorder-boot-restore <<'EOF_CRON_BOOT'
# ONVIF Recorder — auto-reinstall after firmware upgrade.
# NOT managed by dpkg; survives `apt purge`.
# To remove permanently, see CLAUDE.md "Uninstall — full purge".
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
@reboot root /data/onvif-recorder/boot-restore.sh
EOF_CRON_BOOT
chmod 0644 /etc/cron.d/onvif-recorder-boot-restore

cat > /etc/cron.d/onvif-recorder-backup <<'EOF_CRON_BACKUP'
# ONVIF Recorder — daily config backup to /data.
# NOT managed by dpkg; survives `apt purge`.
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
17 4 * * * root /data/onvif-recorder/backup.sh >>/var/log/onvif-recorder-backup.log 2>&1
EOF_CRON_BACKUP
chmod 0644 /etc/cron.d/onvif-recorder-backup

# Sync the auto-reinstall consent with the admin-server setting.
if command -v python3 >/dev/null 2>&1 && [ -f /etc/onvif-recorder/config.json ]; then
    auto=$(python3 -c '
import json
try:
    d = json.load(open("/etc/onvif-recorder/config.json"))
    print("true" if d.get("autoupdate_enabled") else "false")
except Exception:
    print("false")
' 2>/dev/null || echo false)
else
    auto=false
fi
echo "${auto:-false}" > "$DATA_DIR/.autoupdate-consent"

echo ""
echo "==> Recovery layer at $DATA_DIR (boot auto-reinstall: $auto)."
echo "    To opt in/out manually:"
echo "        echo true  > $DATA_DIR/.autoupdate-consent   # enable"
echo "        echo false > $DATA_DIR/.autoupdate-consent   # disable"
echo ""
echo "Done.  Manage it from https://<this-device>/onvif/admin/"
echo "Channel can be changed by editing $CHANNEL_FILE or via the admin UI."
