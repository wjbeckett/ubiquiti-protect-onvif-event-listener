// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * main.cpp -- ONVIF event recorder binary.
 *
 * Uses onvif::OnvifListener to receive events from cameras and:
 *   - optionally writes every parsed event as JSON Lines (--event_log)
 *   - optionally writes every raw SOAP exchange as JSON Lines (--raw_log)
 *   - records human/vehicle detection intervals to the UniFi Protect PostgreSQL DB
 *   - polls motion events from first-party cameras and runs NanoDet-M detection
 */

#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include <atomic>
#include <cstdio>
#include <csignal>
#include <chrono>  // NOLINT(build/c++11)
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/log/log_sink_registry.h"
#include "alarm_notifier.hpp"
#include "contention_profiler.hpp"
#include "cpu_profiler.hpp"
#include "msr_backfill.hpp"
#include "msr_client.hpp"
#include "camera_change_log.hpp"
#include "detection_recorder.hpp"
#include "event_recorder.hpp"
#include "log_ring.hpp"
#include "admin_server.hpp"
#include "log_server.hpp"

// Fallback version string when running outside a .deb install. The admin UI
// prefers `dpkg-query -W -f='${Version}' onvif-recorder` at request time and
// only falls back to this constant if the package is not installed.
#ifndef ONVIF_RECORDER_VERSION
#define ONVIF_RECORDER_VERSION "dev"
#endif
#include "motion_poller.hpp"
#include "object_detect.hpp"
#include "onvif_listener.hpp"
#include "patch_watcher.hpp"
#include "protect_ui_patch.hpp"
#include "runtime_config.hpp"
#include "unifi_camera_config.hpp"
#include "util.hpp"

// ============================================================
// Command-line flags
// ============================================================
ABSL_FLAG(std::string, db_conn,
    "host=/run/postgresql port=5433 dbname=unifi-protect user=postgres",
    "libpq connection string for the UniFi Protect database.");
ABSL_FLAG(std::string, db_host, "",
    "Override the PostgreSQL host for camera config loading "
    "(empty = use /run/postgresql Unix socket).");
ABSL_FLAG(std::string, ubv_dir, "",
    "Directory for per-camera UBV thumbnail files. "
    "Auto-detected on Dream Routers (/srv/unifi-protect/video).");
ABSL_FLAG(int32_t, pre_buffer_sec, 2,
    "Seconds to buffer before the first detection event.");
ABSL_FLAG(int32_t, post_buffer_sec, 2,
    "Seconds to buffer after the last detection event.");
ABSL_FLAG(bool, verbose, false,
    "Enable verbose logging (INFO level): subscription lifecycle, "
    "events received, and renewals. Default logs errors only.");
ABSL_FLAG(int32_t, cpu_profile_hz, 0,
    "Frequency (Hz) at which the CPU profiler samples the call "
    "stacks of all threads via SIGRTMIN+1.  0 disables sampling. "
    "10-100 is typical; output is exposed at /api/cpuz under the "
    "auth-gated admin API.");
ABSL_FLAG(std::string, model_dir, "/usr/share/onvif-recorder/models",
    "Directory containing nanodet_m.param and nanodet_m.bin. "
    "Models are shipped in the Debian package at this path; if missing, "
    "they are downloaded automatically.");
ABSL_FLAG(std::string, state_dir, "/var/lib/onvif-recorder",
    "Directory for persistent runtime state (API-key cache, etc.). "
    "Created on first run if missing.");
ABSL_FLAG(bool, detect, true,
    "Enable NanoDet-M object detection for thumbnail cropping. "
    "Runs as fallback when the camera provides no ONVIF bounding box.");
ABSL_FLAG(bool, detect_override, false,
    "Run NanoDet-M on every thumbnail regardless of whether the camera "
    "provides an ONVIF bounding box. Implies --detect.");
ABSL_FLAG(std::string, event_log, "",
    "Path for the parsed-event JSON Lines log file. "
    "Each line is one ONVIF event with topic, source, data, and timestamp. "
    "Empty (default) disables this log.");
ABSL_FLAG(std::string, raw_log, "",
    "Path for the raw SOAP exchange JSON Lines log file. "
    "Each line is one full HTTP request/response pair (large). "
    "Empty (default) disables this log.");
ABSL_FLAG(std::string, protect_url, "http://localhost:7080",
    "Base URL for the local Protect API used to trigger automations "
    "(e.g. 'Make Sound for detection') on smart detection events.");
ABSL_FLAG(std::string, msr_url, "http://127.0.0.1:7700",
    "Base URL for the local UniFi Media Server Recording (MSR) gRPC "
    "service.  Detection thumbnails are forwarded via "
    "RecordingAPI.StoreSnapshots so that MSR stores them as native UBV "
    "files owned by ms:unifi-streaming — making third-party thumbnails "
    "indistinguishable from first-party camera thumbnails in the "
    "Protect UI.  Default 'http://127.0.0.1:7700' works out of the box "
    "on UniFi Dream Routers/NVRs; set to empty string to disable.");
ABSL_FLAG(int32_t, backfill_msr_thumbnails, 60,
    "Migrate pre-MSR third-party thumbnails from the `thumbnails` table "
    "into native MSR-backed storage by re-uploading each JPEG via "
    "MsrClient::StoreSnapshot and updating events.thumbnailId + "
    "smartDetectObjects.thumbnailId.  Value is the lookback window in "
    "days; 0 disables.  Runs on every startup as a background thread "
    "when --msr_url is set; the query is self-filtering on "
    "LENGTH(thumbnailId)=24, so once the migration is complete, "
    "subsequent startups are effectively a no-op (~16 orphan rows "
    "checked against the thumbnails table, no MSR uploads).");
ABSL_FLAG(bool, backfill_apply, true,
    "When false, --backfill_msr_thumbnails runs as a dry run "
    "(no MSR uploads, no DB writes).  Default true.");
ABSL_FLAG(std::string, protect_user_id, "",
    "X-UserId header value for Protect API auth bypass from localhost. "
    "Obtain with: psql -h /run/postgresql -p 5432 -d unifi-core "
    "-c \"SELECT id FROM users LIMIT 1\"");
ABSL_FLAG(std::string, default_object_type, "person",
    "Object type reported for generic motion events (CellMotionDetector, "
    "VideoSource/MotionAlarm) when the camera does not identify a type. "
    "Valid values: person, vehicle, animal, package.");
ABSL_FLAG(std::string, camera_object_types, "",
    "Per-camera object type overrides as comma-separated ip=type pairs, "
    "e.g. '192.168.1.108=animal,192.168.1.109=package'. "
    "Overrides the detection type for all events from that camera. "
    "Valid types: person, vehicle, animal, package.");
ABSL_FLAG(std::string, rtsp_audio, "",
    "Set enableRtspAudio in the Protect database for all adopted third-party "
    "cameras that have audio capability (hasAudio=true). "
    "Values: 'enable' sets enableRtspAudio=true, 'disable' sets it to false. "
    "Empty (default) leaves the database unchanged.");
ABSL_FLAG(int32_t, coalesce_window_sec, 30,
    "Merge consecutive detections from the same camera into one event if the "
    "new detection starts within this many seconds of the previous one ending. "
    "Set to 0 to disable merging.");
ABSL_FLAG(int32_t, max_events_per_hour, 10,
    "Maximum new detection events created per camera per hour. Events beyond "
    "this limit are dropped to prevent runaway recordings. Set to 0 for unlimited.");
ABSL_FLAG(bool, coalesce_history, true,
    "On startup, scan the last --coalesce_history_days days of events in the "
    "database and merge consecutive detections from the same third-party camera "
    "that are within --coalesce_window_sec of each other.");
ABSL_FLAG(int32_t, coalesce_history_days, 30,
    "Number of days to look back when --coalesce_history is set.");

// --- New flags for first-party support, change log, and rollback ---

ABSL_FLAG(std::string, change_log, "",
    "Path for the cameras-table change log (JSON Lines). Records every "
    "cameras-table modification with old/new values for rollback support. "
    "Empty (default) disables change logging.");
ABSL_FLAG(std::string, rollback, "",
    "Undo cameras-table changes and exit. "
    "Values: 'third_party', 'first_party', 'all'. "
    "Uses --change_log file if it exists; otherwise guesstimates "
    "from current code for third-party cameras.");
ABSL_FLAG(std::string, first_party_cameras, "",
    "Comma-separated camera IDs of first-party cameras to enable smart "
    "detection flags for in the cameras table. Enables the Protect UI "
    "smart detection panel for those cameras.");
ABSL_FLAG(std::string, first_party_camera_models, "",
    "Comma-separated model substrings to match first-party cameras. "
    "For example, 'G3 Instant,G4 Bullet' matches cameras whose type "
    "contains either substring (case-insensitive). Matched cameras are "
    "merged with any explicit --first_party_cameras IDs.");
ABSL_FLAG(int32_t, poll_interval_sec, 10,
    "Seconds between motion-event poll cycles for first-party cameras. "
    "Only active when first-party cameras are discovered.");
ABSL_FLAG(bool, patch_alarm_picker, true,
    "Live-patch the Protect UI (swai.js) to allow third-party cameras "
    "in the alarm creation picker. The patch is idempotent and re-applied "
    "on every startup so it survives firmware updates. The original file "
    "is backed up to swai.js.bak before each patch.");
ABSL_FLAG(uint16_t, log_port, 7890,
    "TCP port for the in-memory log viewer (loopback only). "
    "Served via nginx at /onvif/events/log with Protect auth.");
ABSL_FLAG(uint16_t, admin_port, 7891,
    "TCP port for the package admin page (loopback only). "
    "Served via nginx at /onvif/admin/ with Protect auth.");
ABSL_FLAG(std::string, channel_file, "/etc/onvif-recorder/channel",
    "Path to the APT-channel selector file read/written by the admin page.");

// ============================================================
// Signal handling
// ============================================================
static onvif::OnvifListener* g_listener = nullptr;
static onvif::MotionPoller*  g_poller   = nullptr;

static void signal_handler(int) {
  if (g_listener) g_listener->stop();
  if (g_poller)   g_poller->stop();
}

// ============================================================
// Parse comma-separated IDs into a vector
// ============================================================
static std::vector<std::string> parse_csv(const std::string& s) {
  std::vector<std::string> result;
  size_t pos = 0;
  while (pos < s.size()) {
    size_t comma = s.find(',', pos);
    if (comma == std::string::npos) comma = s.size();
    std::string item = s.substr(pos, comma - pos);
    // Trim whitespace.
    while (!item.empty() && item.front() == ' ') item.erase(item.begin());
    while (!item.empty() && item.back() == ' ')  item.pop_back();
    if (!item.empty()) result.push_back(std::move(item));
    pos = comma + 1;
  }
  return result;
}

// ============================================================
// System information (logged at startup into the ring buffer)
// ============================================================

// Read the installed version of a dpkg package.  Returns empty on failure.
static std::string dpkg_version(const char* pkg) {
  std::string cmd = "dpkg-query -W -f '${Version}' ";
  cmd += pkg;
  cmd += " 2>/dev/null";
  std::FILE* p = popen(cmd.c_str(), "r");  // NOLINT(runtime/int)
  if (!p) return {};
  char buf[128] = {};
  char* ok = std::fgets(buf, sizeof(buf), p);
  pclose(p);  // NOLINT(runtime/int)
  if (!ok) return {};
  // Strip trailing whitespace / newline.
  std::string v(buf);
  while (!v.empty() && (v.back() == '\n' || v.back() == ' '))
    v.pop_back();
  return v;
}

// Read a single-line /proc or /sys file.  Returns empty on failure.
static std::string read_proc_line(const char* path) {
  std::ifstream f(path);
  if (!f) return {};
  std::string line;
  std::getline(f, line);
  // Trim trailing NULs (common in device-tree files).
  while (!line.empty() && line.back() == '\0') line.pop_back();
  return line;
}

static void log_system_info() {
  // Kernel and architecture.
  struct utsname u{};
  if (uname(&u) == 0) {
    LOG(INFO) << "Kernel      : " << u.release
              << " (" << u.machine << ")";
  }

  // CPU cores.
  struct sysinfo si{};
  if (sysinfo(&si) == 0) {
    long pages = sysconf(_SC_PHYS_PAGES);  // NOLINT(runtime/int)
    long psize = sysconf(_SC_PAGE_SIZE);   // NOLINT(runtime/int)
    uint64_t ram_mb = 0;
    if (pages > 0 && psize > 0)
      ram_mb = static_cast<uint64_t>(pages) *
               static_cast<uint64_t>(psize) / (1024 * 1024);
    LOG(INFO) << "Hardware    : " << get_nprocs() << " CPU cores, "
              << ram_mb << " MiB RAM";
  }

  // SoC model from device-tree (e.g. "Annapurna Labs Alpine V2 UBNT").
  std::string soc =
      read_proc_line("/sys/firmware/devicetree/base/model");
  if (!soc.empty())
    LOG(INFO) << "SoC         : " << soc;

  // Key Ubiquiti package versions.
  static const char* kPackages[] = {
      "unifi-core", "unifi-protect", "uos",
      "unifi-native", nullptr};
  for (const char** p = kPackages; *p; ++p) {
    std::string ver = dpkg_version(*p);
    if (!ver.empty())
      LOG(INFO) << "Package     : " << *p << " " << ver;
  }
}

// ============================================================
// Entry point
// ============================================================
int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  // Wire absl's mutex tracer to our per-mutex contention aggregator.
  // Must run before any absl::Mutex traffic — singletons like
  // RawSink and the registered classes self-register from their
  // constructors, but the tracer callback only starts collecting
  // wait-cycle data once installed.
  onvif::ContentionProfiler::install();

  // Always capture INFO+ messages for the in-memory ring buffer.
  // The stderr threshold controls what the user sees in the terminal.
  absl::SetMinLogLevel(absl::LogSeverityAtLeast::kInfo);

  static onvif::LogRing log_ring;
  absl::AddLogSink(&log_ring);

  // Apply config-file overrides BEFORE the first GetFlag read so every
  // subsequent flag access sees the user's saved values from the admin
  // UI.  Empty / missing keys leave the underlying flag untouched.
  const std::string kConfigPath = "/etc/onvif-recorder/config.json";
  runtime_config::LoadFromFile(kConfigPath);

  // Optional periodic CPU sampler.  hz = 0 (default) leaves the
  // sampler dormant; runtime_config can flip it on (the admin
  // Configuration card writes to kConfigPath above).  Must run
  // after LoadFromFile so the flag override is in effect.
  onvif::CpuProfiler::instance().start(absl::GetFlag(FLAGS_cpu_profile_hz));

  const bool verbose = absl::GetFlag(FLAGS_verbose);
  if (verbose) {
    absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
  } else {
    absl::SetStderrThreshold(absl::LogSeverityAtLeast::kError);
  }

  const std::string db_conn     = absl::GetFlag(FLAGS_db_conn);
  const std::string db_host     = absl::GetFlag(FLAGS_db_host);
  const std::string event_log   = absl::GetFlag(FLAGS_event_log);

  // UBV thumbnail directory: use --ubv_dir if set, otherwise auto-detect
  // the native Protect video directory on Dream Routers / NVRs.
  std::string thumbs_dir = absl::GetFlag(FLAGS_ubv_dir);
  if (thumbs_dir.empty()) {
    static const char kProtectVideoDir[] = "/srv/unifi-protect/video";
    struct stat st{};
    if (stat(kProtectVideoDir, &st) == 0 && S_ISDIR(st.st_mode))
      thumbs_dir = kProtectVideoDir;
  }
  const std::string raw_log     = absl::GetFlag(FLAGS_raw_log);
  const std::string change_log  = absl::GetFlag(FLAGS_change_log);
  const std::string rollback    = absl::GetFlag(FLAGS_rollback);
  const std::string fp_cam_str  = absl::GetFlag(FLAGS_first_party_cameras);
  const std::string fp_model_str =
      absl::GetFlag(FLAGS_first_party_camera_models);
  const uint32_t pre_buf_sec    =
      static_cast<uint32_t>(absl::GetFlag(FLAGS_pre_buffer_sec));
  const uint32_t post_buf_sec   =
      static_cast<uint32_t>(absl::GetFlag(FLAGS_post_buffer_sec));

  LOG(INFO) << "ONVIF Event Recorder starting";
  log_system_info();
  LOG(INFO) << "DB conn     : " << db_conn;
  LOG(INFO) << "DB host     : " << (db_host.empty() ? "(default)" : db_host);
  LOG(INFO) << "Pre-buffer  : " << pre_buf_sec << " s";
  LOG(INFO) << "Post-buffer : " << post_buf_sec << " s";
  LOG(INFO) << "Coalesce    : " << absl::GetFlag(FLAGS_coalesce_window_sec) << " s";
  LOG(INFO) << "Max/hr      : " << absl::GetFlag(FLAGS_max_events_per_hour);
  LOG(INFO) << "Event log   : " << (event_log.empty() ? "(disabled)" : event_log);
  LOG(INFO) << "Raw log     : " << (raw_log.empty() ? "(disabled)" : raw_log);
  LOG(INFO) << "Change log  : " << (change_log.empty() ? "(disabled)" : change_log);
  LOG(INFO) << "UBV dir     : " << (thumbs_dir.empty() ? "(disabled)" : thumbs_dir);

  // Camera DB config (shared by all camera-config functions).
  unifi::DbConfig cam_db;
  cam_db.host = db_host.empty() ? "/run/postgresql" : db_host;

  // Parse first-party camera IDs.
  const auto fp_camera_ids = parse_csv(fp_cam_str);

  // ----------------------------------------------------------------
  // Rollback mode: undo cameras-table changes and exit.
  // ----------------------------------------------------------------
  if (!rollback.empty()) {
    if (rollback != "third_party" && rollback != "first_party" &&
        rollback != "all") {
      LOG(ERROR) << "Fatal: --rollback must be 'third_party', "
                 << "'first_party', or 'all' (got '" << rollback << "')";
      return 1;
    }
    // Force verbose for rollback output.
    absl::SetMinLogLevel(absl::LogSeverityAtLeast::kInfo);

    // Cameras-table rollback: best-effort.  On package removal the DB may
    // already be down, but we still want the UI/nginx reverts below to run.
    auto result = unifi::rollback_camera_changes(
        rollback, change_log, fp_camera_ids, cam_db);
    if (!result.ok()) {
      LOG(WARNING) << "[rollback] cameras-table: "
                   << result.status().message();
    } else {
      LOG(INFO) << "[rollback] cameras-table: " << *result
                << " camera(s) updated";
    }

    // Revert Protect UI patches if they were applied.
    auto ui_s = protect_ui::revert_alarm_picker();
    if (!ui_s.ok())
      LOG(WARNING) << "[rollback] " << ui_s.message();

    // Revert nginx log proxy block.
    auto ng_s = protect_ui::revert_nginx_log_proxy();
    if (!ng_s.ok())
      LOG(WARNING) << "[rollback] " << ng_s.message();

    // Revert nginx admin proxy block.
    auto ng_a = protect_ui::revert_nginx_admin_proxy();
    if (!ng_a.ok())
      LOG(WARNING) << "[rollback] " << ng_a.message();

    return 0;
  }

  onvif::global_init();

  // Patch the Protect UI alarm picker to include third-party cameras.
  if (absl::GetFlag(FLAGS_patch_alarm_picker)) {
    auto s = protect_ui::patch_alarm_picker();
    if (s.ok()) {
      LOG(INFO) << "[ui_patch] success";
    } else {
      LOG(WARNING) << "[ui_patch] " << s.message();
    }
  }

  // Start the in-memory log viewer (loopback HTTP, proxied by nginx).
  onvif::LogServer log_server;
  const uint16_t log_port = absl::GetFlag(FLAGS_log_port);
  if (log_server.start(&log_ring, log_port)) {
    LOG(INFO) << "[log_server] listening on 127.0.0.1:" << log_port;
    auto ng = protect_ui::patch_nginx_log_proxy(log_port);
    if (!ng.ok())
      LOG(WARNING) << "[log_server] nginx patch: " << ng.message();
  } else {
    LOG(WARNING) << "[log_server] failed to start on port " << log_port;
  }

  // Discover the Protect API user-id early so the admin server can proxy
  // MSR-stored thumbnails through Protect's local /api/thumbnails/<id>
  // endpoint.  AlarmNotifier (started later) reuses the same value, and
  // also receives the cache_path so it can self-heal across Protect
  // user_id rotations (re-discover on 401, persist back to the cache).
  std::string protect_user_id = absl::GetFlag(FLAGS_protect_user_id);
  const std::string state_dir = absl::GetFlag(FLAGS_state_dir);
  (void)mkdir(state_dir.c_str(), 0755);
  const std::string protect_user_id_cache_path =
      state_dir + "/protect-user-id";
  if (protect_user_id.empty()) {
    struct stat st;
    if (stat(protect_user_id_cache_path.c_str(), &st) != 0) {
      const char kLegacyPath[] = "/root/.config/onvif-recorder-api-key";
      std::ifstream in(kLegacyPath, std::ios::binary);
      if (in.is_open()) {
        std::ofstream out(protect_user_id_cache_path, std::ios::binary);
        if (out.is_open()) {
          out << in.rdbuf();
          LOG(INFO) << "[alarm] migrated cache " << kLegacyPath
                    << " -> " << protect_user_id_cache_path;
        }
      }
    }
    protect_user_id =
        onvif::discover_protect_user_id(protect_user_id_cache_path);
  }

  // Start the admin page (loopback HTTP, proxied at /onvif/admin/).
  onvif::AdminServer admin_server;
  const uint16_t admin_port = absl::GetFlag(FLAGS_admin_port);
  const std::string channel_file = absl::GetFlag(FLAGS_channel_file);
  if (admin_server.start(ONVIF_RECORDER_VERSION, channel_file, admin_port,
                         kConfigPath, cam_db,
                         absl::GetFlag(FLAGS_protect_url),
                         protect_user_id,
                         event_log)) {
    LOG(INFO) << "[admin_server] listening on 127.0.0.1:" << admin_port;
    auto ng_a = protect_ui::patch_nginx_admin_proxy(admin_port);
    if (!ng_a.ok())
      LOG(WARNING) << "[admin_server] nginx patch: " << ng_a.message();
  } else {
    LOG(WARNING) << "[admin_server] failed to start on port " << admin_port;
  }

  // Self-heal across UniFi OS firmware-overlay updates that bypass apt.
  // (apt-driven Protect upgrades fire our dpkg trigger, which restarts
  // the service and re-runs the startup patch pass; the inotify watcher
  // covers the non-dpkg case.)  Re-runs are idempotent: each patch
  // detects "already patched" and no-ops.
  std::unique_ptr<protect_ui::PatchWatcher> patch_watcher;
  if (absl::GetFlag(FLAGS_patch_alarm_picker)) {
    std::vector<protect_ui::WatchSpec> specs = {
      {"/usr/share/unifi-protect/app/node_modules/@ubnt/"
           "unifi-protect-ui-internal/dist",
       {"swai", "vantage"}},
      {"/usr/share/unifi-protect/app", {"service"}},
      {"/data/unifi-core/config/http", {"site-local-ip"}},
    };
    patch_watcher = std::make_unique<protect_ui::PatchWatcher>(
        std::move(specs),
        [log_port, admin_port]() {
          auto sp = protect_ui::patch_alarm_picker();
          if (!sp.ok())
            LOG(WARNING) << "[patch_watcher] alarm picker: " << sp.message();
          auto sl = protect_ui::patch_nginx_log_proxy(log_port);
          if (!sl.ok())
            LOG(WARNING) << "[patch_watcher] nginx log: " << sl.message();
          auto sa = protect_ui::patch_nginx_admin_proxy(admin_port);
          if (!sa.ok())
            LOG(WARNING) << "[patch_watcher] nginx admin: " << sa.message();
        });
    if (!patch_watcher->start())
      LOG(WARNING) << "[patch_watcher] failed to start";
  }

  // Open the change log if configured.
  std::unique_ptr<unifi::CameraChangeLog> change_log_storage;
  unifi::CameraChangeLog* cam_log = nullptr;
  if (!change_log.empty()) {
    auto cl_or = unifi::CameraChangeLog::Create(change_log);
    if (!cl_or.ok()) {
      LOG(ERROR) << "Fatal: " << cl_or.status().message();
      onvif::global_cleanup();
      return 1;
    }
    change_log_storage = std::move(*cl_or);
    cam_log = change_log_storage.get();
  }

  // EventRecorder (optional)
  std::unique_ptr<onvif::EventRecorder> event_rec_storage;
  onvif::EventRecorder* event_rec = nullptr;
  if (!event_log.empty()) {
    auto er_or = onvif::EventRecorder::Create(event_log);
    if (!er_or.ok()) {
      LOG(ERROR) << "Fatal: " << er_or.status().message();
      onvif::global_cleanup();
      return 1;
    }
    event_rec_storage = std::move(*er_or);
    event_rec = event_rec_storage.get();
  }

  // DetectionRecorder
  auto dr_or = onvif::DetectionRecorder::Create(db_conn);
  if (!dr_or.ok()) {
    LOG(ERROR) << "Fatal: " << dr_or.status().message();
    onvif::global_cleanup();
    return 1;
  }
  onvif::DetectionRecorder& det_rec = **dr_or;
  det_rec.set_buffer(pre_buf_sec, post_buf_sec);
  det_rec.set_coalesce_window(
      static_cast<uint32_t>(absl::GetFlag(FLAGS_coalesce_window_sec)));
  det_rec.set_max_events_per_hour(
      static_cast<uint32_t>(absl::GetFlag(FLAGS_max_events_per_hour)));

  // Object type configuration.
  det_rec.set_default_object_type(absl::GetFlag(FLAGS_default_object_type));
  {
    const std::string cam_types = absl::GetFlag(FLAGS_camera_object_types);
    size_t pos = 0;
    while (pos < cam_types.size()) {
      size_t comma = cam_types.find(',', pos);
      if (comma == std::string::npos) comma = cam_types.size();
      const std::string pair = cam_types.substr(pos, comma - pos);
      const size_t eq = pair.find('=');
      if (eq != std::string::npos)
        det_rec.set_camera_object_type(pair.substr(0, eq), pair.substr(eq + 1));
      pos = comma + 1;
    }
  }

  // Load NanoDet-M for thumbnail subject cropping, downloading if needed.
  std::unique_ptr<object_detect::ObjectDetector> detector;
  const std::string model_dir       = absl::GetFlag(FLAGS_model_dir);
  const bool        detect          = absl::GetFlag(FLAGS_detect);
  const bool        detect_override = absl::GetFlag(FLAGS_detect_override);
  if ((detect || detect_override) && !model_dir.empty()) {
    if (!object_detect::ObjectDetector::EnsureModels(model_dir)) {
      LOG(WARNING) << "[detect] model files missing and download failed";
    }
    auto det = object_detect::ObjectDetector::Load(
        model_dir + "/nanodet_m.param",
        model_dir + "/nanodet_m.bin");
    if (det.ok()) {
      detector = std::move(*det);
      det_rec.set_detector(detector.get());
      if (detect_override) {
        det_rec.set_detect_override(true);
        LOG(INFO) << "[detect] override mode: NanoDet-M from " << model_dir;
      } else {
        LOG(INFO) << "[detect] fallback mode: NanoDet-M from " << model_dir;
      }
    } else {
      LOG(WARNING) << "[detect] model not loaded (no ML crop): "
                   << det.status().message();
    }
  }

  onvif::OnvifListener listener;
  g_listener = &listener;
  std::signal(SIGINT,  signal_handler);
  std::signal(SIGTERM, signal_handler);

  if (!thumbs_dir.empty())
    det_rec.set_ubv_dir(thumbs_dir);

  // Always use 24-char hex IDs.  MSR builds its thumbnail index from
  // frames it writes itself; a UBV file dropped on disk is invisible to
  // it, so non-24-char IDs route to MSR TCP and fail with error 414.
  // 24-char hex IDs route to the thumbnails DB table, which we populate
  // directly and which works on all Protect versions.
  const bool use_msr_thumb_ids = false;
  det_rec.set_use_msr_thumbnail_ids(use_msr_thumb_ids);

  // ----------------------------------------------------------------
  // Load third-party cameras from the UniFi Protect database.
  // ----------------------------------------------------------------
  auto cams_or = unifi::load_cameras(cam_db);
  if (!cams_or.ok()) {
    LOG(ERROR) << "Fatal: " << cams_or.status().message();
    onvif::global_cleanup();
    return 1;
  }
  auto cameras = std::move(*cams_or);

  if (auto s = unifi::enable_smart_detect(cameras, cam_db, cam_log); !s.ok()) {
    LOG(ERROR) << "Fatal: " << s.message();
    onvif::global_cleanup();
    return 1;
  }

  if (auto s = unifi::ensure_smart_detect_zones(cameras, cam_db, cam_log);
      !s.ok()) {
    LOG(ERROR) << "Fatal: " << s.message();
    onvif::global_cleanup();
    return 1;
  }

  {
    const std::string rtsp_audio = absl::GetFlag(FLAGS_rtsp_audio);
    if (rtsp_audio == "enable" || rtsp_audio == "disable") {
      const bool enable = (rtsp_audio == "enable");
      if (auto s = unifi::set_rtsp_audio(enable, cam_db, cam_log); !s.ok()) {
        LOG(ERROR) << "Fatal: " << s.message();
        onvif::global_cleanup();
        return 1;
      }
      LOG(INFO) << "[rtsp_audio] " << (enable ? "enabled" : "disabled")
                << " RTSP audio for all cameras with audio capability";
    }
  }

  // ----------------------------------------------------------------
  // First-party camera flag modification
  //   (opt-in via --first_party_cameras and/or --first_party_camera_models).
  // ----------------------------------------------------------------
  // Scoped at function level so the same set of cameras can be fed to the
  // motion poller below.  Otherwise flipping `hasSmartDetect=true` via
  // enable_smart_detect would make these cameras invisible to
  // load_all_nonsmartdetect_first_party, and they'd get flagged as
  // smart-capable in the UI without any software actually classifying
  // their events.
  std::vector<unifi::FirstPartyCamera> fp_cams;
  {
    // Collect cameras from explicit IDs.
    if (!fp_camera_ids.empty()) {
      auto fp_or = unifi::load_first_party_cameras(fp_camera_ids, cam_db);
      if (!fp_or.ok()) {
        LOG(ERROR) << "Warning: " << fp_or.status().message();
      } else {
        fp_cams = std::move(*fp_or);

        // Warn about any IDs that were not found in the DB.
        std::set<std::string> found;
        for (const auto& c : fp_cams) found.insert(c.id);
        for (const auto& id : fp_camera_ids) {
          if (found.find(id) == found.end()) {
            LOG(ERROR) << "[first_party] camera ID " << id
                       << " from --first_party_cameras was NOT found in the "
                       << "cameras table (not adopted or does not exist)";
          }
        }
      }
    }

    // Collect cameras from model substring matches.
    const auto fp_model_subs = parse_csv(fp_model_str);
    if (!fp_model_subs.empty()) {
      auto fp_model_or =
          unifi::load_first_party_cameras_by_model(fp_model_subs, cam_db);
      if (!fp_model_or.ok()) {
        LOG(ERROR) << "Warning: " << fp_model_or.status().message();
      } else {
        const auto& model_cams = *fp_model_or;
        LOG(INFO) << "[first_party] --first_party_camera_models matched "
                  << model_cams.size() << " camera(s)";
        for (const auto& c : model_cams)
          LOG(INFO) << "[first_party]   " << c.id << " (" << c.name << ")";

        // Merge, deduplicating by ID.
        std::set<std::string> existing;
        for (const auto& c : fp_cams) existing.insert(c.id);
        for (const auto& c : model_cams) {
          if (existing.find(c.id) == existing.end()) {
            fp_cams.push_back(c);
            existing.insert(c.id);
          }
        }
      }
    }

    if (!fp_cams.empty()) {
      LOG(INFO) << "[first_party] " << fp_cams.size()
                << " camera(s) matched for flag modification";
      for (const auto& c : fp_cams)
        LOG(INFO) << "[first_party]   " << c.id << " (" << c.name << ")";

      if (auto s = unifi::enable_smart_detect(fp_cams, cam_db, cam_log);
          !s.ok()) {
        LOG(ERROR) << "Warning: " << s.message();
      }
      if (auto s = unifi::ensure_smart_detect_zones(fp_cams, cam_db, cam_log);
          !s.ok()) {
        LOG(ERROR) << "Warning: " << s.message();
      }
    }
  }

  // ----------------------------------------------------------------
  // First-party camera motion polling.
  //
  // Watch list is the union of:
  //   - cameras auto-discovered as not having smart detect (genuine
  //     motion-only models), and
  //   - cameras forced via --first_party_cameras / --first_party_camera_models
  //     above, which now carry hasSmartDetect=true but still need our
  //     software to classify their events.
  // ----------------------------------------------------------------
  std::unique_ptr<onvif::MotionPoller> motion_poller;
  {
    std::vector<std::string> fp_ids;
    std::map<std::string, std::string> fp_macs;
    std::set<std::string> seen;

    auto add_camera = [&](const std::string& id,
                          const std::string& name,
                          const std::string& mac) {
      if (id.empty() || !seen.insert(id).second) return;
      fp_ids.push_back(id);
      if (!mac.empty()) fp_macs[id] = mac;
      LOG(INFO) << "[motion_poller]   " << id << " (" << name << ")";
    };

    for (const auto& c : fp_cams) add_camera(c.id, c.name, c.mac);

    auto fp_all_or = unifi::load_all_nonsmartdetect_first_party(cam_db);
    if (fp_all_or.ok()) {
      for (const auto& c : *fp_all_or) add_camera(c.id, c.name, c.mac);
    } else {
      LOG(WARNING) << "[motion_poller] "
                   << fp_all_or.status().message();
    }

    if (!fp_ids.empty() && detector) {
      LOG(INFO) << "[motion_poller] watching " << fp_ids.size()
                << " first-party camera(s)";
      auto mp_or = onvif::MotionPoller::Create(db_conn);
      if (mp_or.ok()) {
        motion_poller = std::move(*mp_or);
        motion_poller->set_camera_ids(fp_ids);
        motion_poller->set_camera_macs(fp_macs);
        motion_poller->set_detector(detector.get());
        if (!thumbs_dir.empty())
          motion_poller->set_ubv_dir(thumbs_dir);
        motion_poller->set_poll_interval(
            absl::GetFlag(FLAGS_poll_interval_sec));
        motion_poller->set_coalesce_window(
            static_cast<uint32_t>(absl::GetFlag(FLAGS_coalesce_window_sec)));
        motion_poller->set_use_msr_thumbnail_ids(use_msr_thumb_ids);
        motion_poller->set_protect_api(
            absl::GetFlag(FLAGS_protect_url), protect_user_id);
      } else {
        LOG(ERROR) << "[motion_poller] " << mp_or.status().message();
      }
    } else if (!fp_ids.empty() && !detector) {
      LOG(INFO) << "[motion_poller] " << fp_ids.size()
                << " first-party camera(s) found but --detect/--model_dir "
                << "not set; motion polling disabled";
    }
  }

  // AlarmNotifier: triggers Protect automations (e.g. chime play) on
  // detections.  user-id was discovered earlier (above admin_server.start).
  std::unique_ptr<onvif::AlarmNotifier> alarm_notifier;
  if (!protect_user_id.empty()) {
    alarm_notifier = std::make_unique<onvif::AlarmNotifier>(
        absl::GetFlag(FLAGS_protect_url), protect_user_id, db_conn,
        protect_user_id_cache_path);
    alarm_notifier->refresh_alarms();
    det_rec.set_alarm_notifier(alarm_notifier.get());
  } else {
    LOG(INFO) << "[alarm] user ID not found; automation triggers disabled";
  }
  if (motion_poller && alarm_notifier)
    motion_poller->set_alarm_notifier(alarm_notifier.get());

  // MsrClient: forwards thumbnails to MSR so Protect serves them via MSP TCP.
  std::unique_ptr<onvif::MsrClient> msr_client;
  {
    const std::string msr_url = absl::GetFlag(FLAGS_msr_url);
    if (!msr_url.empty()) {
      msr_client = std::make_unique<onvif::MsrClient>(msr_url);
      det_rec.set_msr_client(msr_client.get());
      LOG(INFO) << "[msr] StoreSnapshots forwarding enabled: " << msr_url;
    }
  }

  // Backfill pre-MSR third-party thumbnails in the background.  Runs on
  // every startup when --msr_url is set; the SQL candidate query filters
  // on LENGTH(thumbnailId)=24, so it becomes a cheap no-op once all
  // eligible events have been migrated.  A background thread keeps the
  // event loop responsive while the migration runs.
  std::thread backfill_thread;
  {
    const int  days  = absl::GetFlag(FLAGS_backfill_msr_thumbnails);
    const bool apply = absl::GetFlag(FLAGS_backfill_apply);
    if (days > 0 && msr_client) {
      onvif::MsrClient* msr_ptr = msr_client.get();
      backfill_thread = std::thread([db_conn, msr_ptr, days, apply]() {
        onvif::msr_backfill::run(db_conn, msr_ptr, days, apply);
      });
    } else if (days > 0 && apply) {
      LOG(INFO) << "[backfill] skipped: --msr_url not set";
    }
  }

  // Optional startup coalescing: merge nearby events already in the database.
  // Purge stuck-open events (end IS NULL older than 5 minutes) left behind
  // by a previous crash or rapid-fire "started" bursts from cameras.
  // Must run before coalesce_history so the NULL-end rows don't interfere.
  {
    const int n = det_rec.purge_stale_open_events(300000);
    if (n > 0)
      LOG(INFO) << "[startup] purged " << n << " stuck-open event(s)";
  }

  if (absl::GetFlag(FLAGS_coalesce_history)) {
    const int days = absl::GetFlag(FLAGS_coalesce_history_days);
    LOG(INFO) << "[coalesce_history] scanning last " << days << " day(s)...";
    const int n = det_rec.coalesce_history(days);
    LOG(INFO) << "[coalesce_history] done (" << n << " event(s) merged)";
  }

  // Purge rows orphaned by coalesce operations across all dependent tables
  // (smartDetectRaws, thumbnails, smartDetectObjects, detectionLabels).
  {
    const int n = det_rec.purge_orphaned_rows();
    if (n > 0)
      LOG(INFO) << "[startup] purged " << n << " orphaned row(s)";
  }

  for (auto cam : cameras) {
    cam.max_consecutive_failures = 3;
    listener.add_camera(cam);
    det_rec.set_snapshot(cam);
    LOG(INFO) << "Watching camera " << cam.ip;
  }

  if (cameras.empty() && !motion_poller) {
    LOG(WARNING) << "No third-party cameras found in Protect and no "
                 << "first-party cameras configured for motion polling; "
                 << "service will stay alive but idle. Add a third-party "
                 << "ONVIF camera in Protect or pass "
                 << "--first_party_cameras / --first_party_camera_models "
                 << "to do useful work.";
  }

  if (!raw_log.empty())
    listener.enable_raw_recording(raw_log);

  // Start the motion poller before the listener (non-blocking).
  if (motion_poller) {
    g_poller = motion_poller.get();
    motion_poller->start();
  }

  // Background rescan thread: periodically re-query Protect's cameras
  // table and hot-add any cameras that appear after startup.  Lets users
  // add a third-party camera in Protect without restarting the service.
  std::atomic<bool> rescan_running{true};
  std::set<std::string> known_ids;
  for (const auto& c : cameras) known_ids.insert(c.id);
  std::thread rescan_thread([&]() {
    constexpr int kPollSec = 60;
    while (rescan_running) {
      for (int i = 0; i < kPollSec && rescan_running; ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
      if (!rescan_running) break;

      auto reloaded = unifi::load_cameras(cam_db);
      if (!reloaded.ok()) {
        LOG(WARNING) << "[rescan] load_cameras: "
                     << reloaded.status().message();
        continue;
      }
      std::vector<onvif::CameraConfig> fresh;
      for (const auto& c : *reloaded)
        if (!known_ids.count(c.id)) fresh.push_back(c);
      if (fresh.empty()) continue;

      LOG(INFO) << "[rescan] detected " << fresh.size()
                << " new third-party camera(s)";
      if (auto s = unifi::enable_smart_detect(fresh, cam_db, cam_log);
          !s.ok())
        LOG(WARNING) << "[rescan] enable_smart_detect: " << s.message();
      if (auto s = unifi::ensure_smart_detect_zones(fresh, cam_db, cam_log);
          !s.ok())
        LOG(WARNING) << "[rescan] ensure_smart_detect_zones: "
                     << s.message();
      for (auto cam : fresh) {
        cam.max_consecutive_failures = 3;
        known_ids.insert(cam.id);
        det_rec.set_snapshot(cam);
        listener.add_camera_live(cam);
        LOG(INFO) << "Watching camera " << cam.ip;
      }
    }
  });

  listener.run([event_rec, &det_rec](const onvif::OnvifEvent& ev) {
    if (event_rec) event_rec->write(ev);
    det_rec.on_event(ev);
  });

  // Clean shutdown.
  rescan_running = false;
  if (rescan_thread.joinable())
    rescan_thread.join();
  if (motion_poller)
    motion_poller->stop();
  if (backfill_thread.joinable())
    backfill_thread.join();
  g_poller   = nullptr;
  g_listener = nullptr;
  onvif::global_cleanup();
  LOG(INFO) << "Done";
  return 0;
}
