# ONVIF Event Recorder

Bridges **third-party ONVIF cameras** into UniFi Protect. It listens to ONVIF
WS-PullPoint event streams and writes detection events (person, vehicle, animal,
package) to the UniFi Protect PostgreSQL database so they appear natively in the
Protect UI — including timeline clips, thumbnails, smart detection search, and
security alarms.

It can also add smart detection to **first-party UniFi cameras that lack native
AI** (e.g. G3 Instant). See [First-party camera support](#first-party-camera-support).

---

## Installation on Dream Router / Dream Machine

### Windows installer (no terminal required)

If you're on Windows and don't want to touch SSH directly, download the
latest `OnvifRecorderInstaller-v*.exe` from
[Releases](https://github.com/danielwoz/ubiquiti-protect-onvif-event-listener/releases)
and run it. The GUI:

1. Walks you through enabling SSH on your router
   (**UniFi OS → System → Advanced → SSH**).
2. Tests the connection with the root password you set.
3. Adds the apt repository + installs the package, streaming progress live.
4. Saves the credentials (password encrypted with Windows DPAPI) in
   `HKCU\Software\OnvifRecorderInstaller` so subsequent launches offer
   one-click upgrade, re-install, or uninstall.

The installer is unsigned, so Windows SmartScreen will prompt the first
time — click **More info → Run anyway**.

### One-line install (recommended for macOS/Linux users)

SSH to your UniFi device and run:

```bash
curl -fsSL https://danielwoz.github.io/ubiquiti-protect-onvif-event-listener/install.sh | sh
```

That's it. The installer:

1. Installs the signing key to `/usr/share/keyrings/onvif-recorder-archive-keyring.gpg`.
2. Detects your UniFi Protect release channel (Stable / Release Candidate /
   Early Access) and configures APT to pull matching builds.
3. `apt-get install onvif-recorder`, which auto-enables the systemd service
   plus two daily timers: channel sync and auto-updates.

Detections will appear in UniFi Protect within seconds of the first motion
event. Service logs land in journald (`journalctl -u onvif-recorder`).

**What happens on first start:**

1. The Protect user ID is **auto-discovered** from the unifi-core database
   and cached to `/var/lib/onvif-recorder/protect-user-id`.
2. The Protect UI is **live-patched** so third-party cameras appear in the
   alarm creation picker.
3. nginx is patched to expose the admin UI at `https://<device>/onvif/admin/`.
4. Third-party ONVIF cameras are loaded from the Protect database and smart
   detection flags are enabled for them.

No flags are required for the default setup.

### Admin UI

After install, manage the package without SSH at
`https://<device>/onvif/admin/`:

- Force an update check
- Switch release channel (stable / rc / early-access)
- Enable / disable auto-updates and change the schedule
- Uninstall the package

### Updates

Auto-updates are **on by default**. The `onvif-recorder-autoupdate.timer` runs
daily with up to 2h random jitter; `onvif-recorder-channel.timer` keeps the
APT suite in sync with your Protect channel. Both can be disabled via the
admin UI or `systemctl disable --now <timer>`.

### Uninstall

```bash
apt-get remove onvif-recorder          # stops service, rolls back DB changes
apt-get purge  onvif-recorder          # also removes /etc/onvif-recorder and state
```

### Legacy install (deprecated)

Prior releases shipped as a raw binary at `/root/onvif_recorder`. The `.deb`
postinst migrates an existing manual install automatically on first upgrade —
no action required.

---

## Configuration flags

All options are set via command-line flags. To change a flag, edit the
service file's `ExecStart` line (usually via a systemd drop-in):

```bash
# systemctl edit onvif-recorder.service
# then add (or amend) an [Service] section:
[Service]
ExecStart=
ExecStart=/usr/bin/onvif-recorder --verbose --detect_override
```

```bash
systemctl daemon-reload && systemctl restart onvif-recorder
```

### Detection object types

The recorder maps ONVIF camera events to four UniFi Protect smart-detection types:

| Type | How it is produced |
|------|--------------------|
| `person` | FieldDetector "Human", HumanShapeDetect, Reolink PeopleDetect, or any generic motion event when `--default_object_type=person` (the factory default) |
| `vehicle` | FieldDetector "Vehicle", VehicleDetect, Reolink VehicleDetect, or generic motion when `--default_object_type=vehicle` |
| `animal` | Generic motion when `--default_object_type=animal`, or any camera whose events are overridden via `--camera_object_types` |
| `package` | Generic motion when `--default_object_type=package`, or any camera whose events are overridden via `--camera_object_types` |

**Generic motion events** (CellMotionDetector, VideoSource/MotionAlarm) carry no
object class. By default the recorder uses `--default_object_type` for these.
When NanoDet-M is enabled (the default), the detected COCO class overrides the
default type — so a snapshot containing a car is stored as `vehicle` even though
the camera reported only "motion". Per-camera `--camera_object_types` overrides
always take priority over NanoDet-M.

AI-specific events (Human/Vehicle detections from FieldDetector, HumanShapeDetect,
etc.) are never affected by `--default_object_type` or NanoDet-M class inference.

**Per-camera overrides** (`--camera_object_types`) replace the detection type for
every event from the named camera, including AI events. This is useful for
wildlife cameras or entrance monitors where you always want a specific type
regardless of what the camera reports.

| Flag | Default | Description |
|------|---------|-------------|
| `--default_object_type` | `person` | Object type written for generic motion events that carry no object class. Valid values: `person`, `vehicle`, `animal`, `package`. |
| `--camera_object_types` | _(disabled)_ | Comma-separated `ip=type` overrides applied to all events from each named camera, e.g. `192.168.1.108=animal,192.168.1.109=package`. |

**Example — wildlife camera on `.108` and package camera on `.109`:**
```bash
ExecStart=/usr/bin/onvif-recorder \
  --camera_object_types=192.168.1.108=animal,192.168.1.109=package
```

---

### Security alarms

The recorder integrates with the UniFi Protect automation system so that ONVIF
camera detections can trigger automations (sound, push notification, webhook,
unlock door, light, PTZ preset) configured in **Protect → Alarms**.

**How it works:**

1. At startup the recorder live-patches the Protect UI so third-party cameras
   appear in the alarm creation scope picker.
2. The recorder refreshes the list of configured automations from the Protect API
   every five minutes.
3. When a detection event is recorded, the recorder triggers matching automations
   via the local Protect API (port 7080), records history in `automationsHistory`
   so hits appear in the Protect UI, and respects the "ignore repeated" cooldown
   setting on each automation.

**Setup:**

1. In Protect, create a new alarm under **Protect → Alarms → New alarm**.
2. Set the scope to include your ONVIF cameras and choose the trigger types you
   want (person, vehicle, animal, and/or package).
3. Choose one or more actions: sound, push notification, webhook, etc.
4. Your ONVIF cameras will fire the alarm on matching detections.

| Flag | Default | Description |
|------|---------|-------------|
| `--protect_url` | `http://localhost:7080` | Base URL for the local Protect API. Only change this if running off-device. |
| `--protect_user_id` | _(auto-discovered)_ | Protect user ID for API auth. Auto-discovered from the unifi-core DB and cached to `/var/lib/onvif-recorder/protect-user-id`. Pass explicitly to override. |
| `--patch_alarm_picker` | `true` | Live-patch the Protect UI so third-party cameras appear in the alarm creation picker. |

---

### NanoDet-M object detection

NanoDet-M is enabled by default for thumbnail subject cropping and object
classification. Model files are **downloaded automatically** on first startup if
not present in `--model_dir`.

> **Performance (Dream Router — 4 x Cortex-A55 cores):**
> NanoDet-M takes ~158 ms per inference on one core (ARM64 NEON build).
> At 1 detection/minute this is 0.26% of 1 core = **0.065% of total CPU**.
> Even at 5 detections/minute across multiple cameras you are well under 0.5%
> of total device CPU.

| Flag | Default | Description |
|------|---------|-------------|
| `--model_dir` | `/usr/share/onvif-recorder/models` | Directory for NanoDet-M model files. Shipped inside the .deb. |
| `--detect` | `true` | Run NanoDet-M as fallback when the camera provides no ONVIF bounding box. |
| `--detect_override` | `false` | Always run NanoDet-M, ignoring any ONVIF bounding box. Implies `--detect`. |

**Thumbnail crop priority:**
1. `--detect_override` set: always use NanoDet-M
2. Camera provides an ONVIF bounding box: crop to that box
3. `--detect` set and no ONVIF box: run NanoDet-M, fall back to full image
4. `--nodetect`: full uncropped image when no ONVIF box

To disable NanoDet-M entirely, pass `--nodetect`.

---

### First-party camera support

The recorder can add smart detection to **first-party UniFi cameras that lack
native AI** (e.g. UVC G3 Instant). These cameras already generate `motion` events
in Protect with thumbnails — the recorder polls for those events, runs NanoDet-M
on the existing thumbnail, and inserts smart detection records when a person,
vehicle, or animal is found.

**How it works:**

1. On startup the recorder auto-discovers all adopted first-party cameras where
   `featureFlags.hasSmartDetect` is null or false.
2. A background thread polls the `events` table for completed `motion` events
   from those cameras.
3. For each motion event, the recorder fetches the thumbnail Protect already
   stored, runs NanoDet-M, and — if a relevant subject is detected — inserts
   a `smartDetectZone` event with all associated records (thumbnail, smart
   detect object, smart detect raw, alarm notification).

**Optional: enable the Protect UI smart detection panel** for specific cameras
by passing their database IDs via `--first_party_cameras`. This updates
`featureFlags.smartDetectTypes` and `smartDetectZones` in the cameras table so
the Protect UI shows smart detections for those cameras. Without this flag,
detections are still recorded and alarms still fire — you just won't see them
in the smart detection timeline filter.

To find your camera IDs, run on the router:

```sql
psql -h /run/postgresql -p 5433 -U postgres unifi-protect -c "
SELECT id, name, model
FROM cameras
WHERE \"isThirdPartyCamera\" = false AND \"isAdopted\" = true
ORDER BY name;
"
```

| Flag | Default | Description |
|------|---------|-------------|
| `--first_party_cameras` | _(disabled)_ | Comma-separated camera IDs to enable smart detection flags for. Only needed for the Protect smart detection UI. |
| `--poll_interval_sec` | `10` | Seconds between motion-event poll cycles. |

**Example — enable G3 Instant smart detection with UI support:**
```bash
ExecStart=/usr/bin/onvif-recorder --detect_override \
  --first_party_cameras=6713fe0a01583d03e400051c,6713fa9e023c3d03e4000451
```

---

### Change log and rollback

The recorder can log every cameras-table modification it makes to a JSON Lines
file and undo those changes on demand.

| Flag | Default | Description |
|------|---------|-------------|
| `--change_log` | _(disabled)_ | Path for the cameras-table change log (JSON Lines). |
| `--rollback` | _(disabled)_ | Undo cameras-table changes and **exit**. Values: `third_party`, `first_party`, `all`. |

When `--rollback` is set, the recorder reads the change log (if it exists),
applies the original values back to the database, and exits. If no change log
file exists and the scope includes third-party cameras, the recorder performs a
best-effort reset.

**Example — enable change logging:**
```bash
ExecStart=/usr/bin/onvif-recorder \
  --change_log=/var/lib/onvif-recorder/cam_changes.jsonl
```

**Example — rollback all changes and exit:**
```bash
/usr/bin/onvif-recorder --rollback=all \
  --change_log=/var/lib/onvif-recorder/cam_changes.jsonl
```

---

### Other flags

| Flag | Default | Description |
|------|---------|-------------|
| `--db_conn` | `host=/run/postgresql port=5433 dbname=unifi-protect user=postgres` | libpq connection string for the Protect database. |
| `--db_host` | _(empty = Unix socket)_ | Override PostgreSQL host for camera config loading. |
| `--ubv_dir` | _(auto-detected)_ | Directory for per-camera UBV thumbnail files. Auto-detected on Dream Routers (`/srv/unifi-protect/video`). |
| `--rtsp_audio` | _(disabled)_ | Set RTSP audio in the Protect database: `enable` or `disable`. |
| `--pre_buffer_sec` | `2` | Seconds before the first detection to mark as clip start. |
| `--post_buffer_sec` | `2` | Seconds after the last detection to mark as clip end. |
| `--coalesce_window_sec` | `30` | Merge consecutive detections within this window into one event. `0` to disable. |
| `--max_events_per_hour` | `10` | Maximum new events per camera per hour. `0` for unlimited. |
| `--coalesce_history` | `true` | On startup, merge consecutive historical detections within `--coalesce_window_sec`. |
| `--coalesce_history_days` | `30` | Days to look back for history coalescing. |
| `--verbose` | `false` | Enable INFO-level logging (lifecycle, events, renewals). |
| `--event_log` | _(disabled)_ | Path for parsed-event JSON Lines log. |
| `--raw_log` | _(disabled)_ | Path for raw SOAP exchange JSON Lines log (large). |

---

## Troubleshooting

**Check the log for errors:**
```bash
journalctl -u onvif-recorder -f
```

**Enable verbose output** to see per-camera lifecycle events:
```bash
systemctl stop onvif-recorder
/usr/bin/onvif-recorder --verbose
```

**Camera not working?** Capture a raw diagnostic log and open a GitHub issue:
```bash
/usr/bin/onvif-recorder --verbose --raw_log=/tmp/onvif-raw.jsonl
# Let it run 60+ seconds, then Ctrl+C
# Attach /tmp/onvif-raw.jsonl to your issue
```

**Camera went offline and did not reconnect?** The recorder automatically retries.
After 3 consecutive failures it pauses for up to 1 hour, then resumes. If a camera
reboot takes longer than expected, restart the service:
```bash
systemctl restart onvif-recorder
```

---

## Building from source

### Prerequisites

- **Ubuntu 24.04** x86_64 build host (Ubuntu 22.04 also works)
- [Bazelisk](https://github.com/bazelbuild/bazelisk) installed at `~/.local/bin/bazel`
- Git with submodule support

### 1. Clone with submodules

```bash
git clone --recurse-submodules https://github.com/danielwoz/ubiquiti-protect-onvif-event-listener.git
cd ubiquiti-protect-onvif-event-listener
```

If you already cloned without `--recurse-submodules`:

```bash
git submodule update --init --recursive
```

### 2. Install Bazelisk

```bash
mkdir -p ~/.local/bin
curl -fsSL https://github.com/bazelbuild/bazelisk/releases/latest/download/bazelisk-linux-amd64 \
  -o ~/.local/bin/bazel
chmod +x ~/.local/bin/bazel
```

### 3. Install apt dependencies

All C libraries are built from source via Bazel. Only build tools are needed:

```bash
sudo apt-get install -y \
  build-essential clang cmake ninja-build perl \
  python3-cpplint
```

### 4. Build

```bash
# x86_64 native binary
scripts/bz build --config=x86 //:onvif_recorder

# ARM64 release binary (PGO + ThinLTO, for Dream Router / Dream Machine)
scripts/bz build --config=arm64_release //:onvif_recorder

# All tests
scripts/bz test --config=x86 //test:all
```

The ARM64 build downloads its own sysroot automatically — no manual cross-toolchain
setup is required.

### Runtime dependencies (ARM64)

The ARM64 binary is almost entirely statically linked:

```
libm.so.6  libc.so.6  ld-linux-aarch64.so.1  libgcc_s.so.1
```

### Runtime dependencies (x86_64)

```
libm.so.6  libc.so.6  ld-linux-x86-64.so.1  libgcc_s.so.1
libldap.so.2  liblber.so.2
```

---

## Project structure

```
main.cpp                      — Binary entry point
onvif_listener.hpp/.cpp       — WS-PullPoint ONVIF subscription library
detection_recorder.hpp/.cpp   — Detection -> PostgreSQL recorder
alarm_notifier.hpp/.cpp       — Protect automation trigger + history
motion_poller.hpp/.cpp        — First-party camera motion -> smart detect poller
camera_change_log.hpp/.cpp    — Cameras-table change log and rollback
protect_ui_patch.hpp/.cpp     — Live-patch Protect UI alarm picker
ubv_thumbnail.hpp/.cpp        — UBV container encode/decode
jpeg_crop.hpp/.cpp            — JPEG decode/crop/re-encode via libjpeg
object_detect.hpp/.cpp        — NanoDet-M object detection via NCNN
unifi_camera_config.hpp/.cpp  — Load camera credentials from Protect DB
```
