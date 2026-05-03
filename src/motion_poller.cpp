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

#include "motion_poller.hpp"

#include <curl/curl.h>
#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "alarm_notifier.hpp"
#include "jpeg_crop.hpp"
#include "object_detect.hpp"
#include "protect_user_id_provider.hpp"
#include "ubv_thumbnail.hpp"
#include "util.hpp"

namespace onvif {

// ---------------------------------------------------------------------------
// Helpers (exposed via namespace motion_poller_internal for testing)
// ---------------------------------------------------------------------------

namespace motion_poller_internal {

std::string smart_detect_types_json(const std::string& det_type) {
  if (det_type == "vehicle") return "[\"vehicle\"]";
  if (det_type == "animal")  return "[\"animal\"]";
  if (det_type == "package") return "[\"package\"]";
  return "[\"person\"]";
}

std::string build_sdr_payload(uint64_t ts_ms, const std::string& obj_type,
                              int confidence) {
  const std::string ts = std::to_string(ts_ms);
  const std::string conf_str = std::to_string(confidence);
  return
      std::string("{")
      + "\"attributesForTracks\":null,"
      + "\"clockStream\":" + ts + ","
      + "\"clockStreamRate\":1000,"
      + "\"clockWall\":" + ts + ","
      + "\"descriptors\":[{"
      + "\"attributes\":null,"
      + "\"confidence\":" + conf_str + ","
      + "\"coord\":[-1.0,-1.0,-1.0,-1.0],"
      + "\"coord3d\":[-1.0,-1.0],"
      + "\"depth\":null,"
      + "\"duration\":0,"
      + "\"firstShownTimeMs\":" + ts + ","
      + "\"id\":\"1\","
      + "\"idleSinceTimeMs\":" + ts + ","
      + "\"licensePlate\":null,"
      + "\"lines\":[],"
      + "\"loiterZones\":[],"
      + "\"matchedId\":null,"
      + "\"name\":\"\","
      + "\"objectType\":\"" + obj_type + "\","
      + "\"speed\":null,"
      + "\"stationary\":false,"
      + "\"timestamp\":" + ts + ","
      + "\"zones\":[]"
      + "}],"
      + "\"edgeType\":\"none\","
      + "\"linesStatus\":null,"
      + "\"loiterZonesStatus\":null,"
      + "\"smartDetectSnapshotFullFoV\":\"\","
      + "\"smartDetectSnapshots\":null,"
      + "\"tamperStatus\":null,"
      + "\"trackerIdAttrMap\":null,"
      + "\"zonesStatus\":{}"
      + "}";
}

std::string build_sdo_attributes(const std::string& obj_type, int confidence) {
  // Mirrors the attributes column shape that native first-party
  // smartDetectZone events write.  Nulls are sentinels Protect's UI /
  // iOS app expect to be present (not absent).  trackerId=1 because we
  // only emit one detection per event; zone=[] because we do not
  // currently propagate zone IDs.
  return std::string("{")
      + "\"associatedFaceTrackerID\":null,"
      + "\"blurness\":null,"
      + "\"color\":null,"
      + "\"confidence\":" + std::to_string(confidence) + ","
      + "\"faceEmbed\":null,"
      + "\"faceLandmarks\":null,"
      + "\"faceMask\":null,"
      + "\"facePose\":null,"
      + "\"faceVerifyStatus\":null,"
      + "\"line\":null,"
      + "\"matchedId\":null,"
      + "\"matchedName\":null,"
      + "\"namesTopK\":null,"
      + "\"objectType\":\"" + obj_type + "\","
      + "\"personEmbedFromCamera\":null,"
      + "\"qualityScore\":null,"
      + "\"topKCandidate\":null,"
      + "\"trackerId\":1,"
      + "\"vehicleType\":null,"
      + "\"zone\":[]"
      + "}";
}

std::string build_sdt_payload(uint64_t start_ms,
                               uint64_t end_ms,
                               const std::string& obj_type,
                               int confidence) {
  // Native Protect writes one row in smartDetectTracks per event,
  // payload = JSON array of track samples.  We only have one detection
  // per event so the array carries a single entry.  duration is in
  // seconds in native rows; coord is unknown (we don't propagate
  // pixel-space bbox here) so use the same [-1, -1, -1, -1] sentinel
  // smartDetectRaws uses.
  const uint64_t duration_sec =
      (end_ms > start_ms) ? (end_ms - start_ms) / 1000 : 0;
  const std::string start_str = std::to_string(start_ms);
  const std::string end_str   = std::to_string(end_ms);
  const std::string conf_str  = std::to_string(confidence);
  const std::string dur_str   = std::to_string(duration_sec);
  return std::string("[{")
      + "\"attributes\":null,"
      + "\"confidence\":" + conf_str + ","
      + "\"coord\":[-1.0,-1.0,-1.0,-1.0],"
      + "\"coord3d\":[-1.0,-1.0],"
      + "\"depth\":null,"
      + "\"duration\":" + dur_str + ","
      + "\"firstShownTimeMs\":" + start_str + ","
      + "\"id\":\"1\","
      + "\"idleSinceTimeMs\":0,"
      + "\"licensePlate\":null,"
      + "\"lines\":[],"
      + "\"loiterZones\":[],"
      + "\"matchedId\":null,"
      + "\"name\":\"\","
      + "\"objectType\":\"" + obj_type + "\","
      + "\"speed\":null,"
      + "\"stationary\":false,"
      + "\"timestamp\":" + end_str + ","
      + "\"zones\":[]"
      + "}]";
}

}  // namespace motion_poller_internal

namespace {

// One-shot HTTP GET to the Protect API.  Returns (http_code, body).
// http_code == 0 indicates a curl-level failure (network/timeout).
struct ProtectGetResult {
  long code;  // NOLINT(runtime/int)
  std::vector<uint8_t> body;
};
ProtectGetResult perform_protect_get(const std::string& base_url,
                                     const std::string& user_id,
                                     const std::string& thumb_id) {
  ProtectGetResult out{0, {}};
  if (base_url.empty() || user_id.empty()) return out;
  const std::string url = base_url + "/api/thumbnails/" + thumb_id;
  std::string buf;
  CURL* curl = curl_easy_init();
  if (!curl) return out;
  struct curl_slist* hdrs = nullptr;
  const std::string user_hdr = "X-UserId: " + user_id;
  hdrs = curl_slist_append(hdrs, user_hdr.c_str());
  hdrs = curl_slist_append(hdrs, "X-Source: unifi-os");
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);  // NOLINT(runtime/int)
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // NOLINT(runtime/int)
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
      +[](char* p, size_t s, size_t n, void* ud) -> size_t {
        static_cast<std::string*>(ud)->append(p, s * n);
        return s * n;
      });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
  const CURLcode rc = curl_easy_perform(curl);
  if (rc == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &out.code);
  }
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);
  if (out.code == 200) {
    out.body.assign(buf.begin(), buf.end());
  }
  return out;
}

// GET <protect_url>/api/thumbnails/<id> with X-UserId auth.  Returns
// the JPEG bytes on 200, or an empty vector on any error / non-200.
// Used to pull MSR-format (non-24-char) thumbnails that Protect stores
// as native UBV files served by the msp media server, since those never
// land in the Postgres `thumbnails` table.
//
// On observed 401, asks the provider to re-discover the user_id and
// retries the request once with the new value.
std::vector<uint8_t> fetch_thumbnail_via_protect(
    const std::string& base_url,
    ProtectUserIdProvider* provider,
    const std::string& thumb_id) {
  if (base_url.empty() || !provider) return {};
  ProtectGetResult r = perform_protect_get(base_url, provider->current(),
                                            thumb_id);
  if (r.code == 401 && provider->try_refresh()) {
    LOG(INFO) << "[motion_poller] retrying thumbnail GET after user_id refresh";
    r = perform_protect_get(base_url, provider->current(), thumb_id);
  }
  return r.body;
}

}  // namespace

// ---------------------------------------------------------------------------
// Implementation struct
// ---------------------------------------------------------------------------

struct MotionPoller::Impl {
  PGconn* conn{nullptr};
  std::vector<std::string> camera_ids;
  std::map<std::string, std::string> id_to_mac;
  const object_detect::ObjectDetector* detector{nullptr};
  AlarmNotifier* alarm_notifier{nullptr};
  std::string ubv_dir;
  std::string protect_url;       // empty = HTTP-fallback disabled
  ProtectUserIdProvider* protect_user_id_provider{nullptr};
  int poll_interval_sec{10};
  uint32_t coalesce_window_sec{30};
  bool use_msr_thumb_ids{false};

  // UBV path cache: MAC -> (date string, file path).
  std::map<std::string, std::pair<std::string, std::string>> ubv_cache;

  // High-water mark: last processed motion event start per camera.
  std::map<std::string, uint64_t> hwm;

  ~Impl() {
    if (conn) PQfinish(conn);
  }

  // Attempt to restore a broken connection.
  void maybe_reconnect() {
    if (PQstatus(conn) != CONNECTION_BAD) return;
    LOG(WARNING) << "[motion_poller] connection lost — reconnecting";
    PQreset(conn);
    if (PQstatus(conn) == CONNECTION_OK)
      LOG(INFO) << "[motion_poller] reconnected";
    else
      LOG(ERROR) << "[motion_poller] reconnect failed: "
                 << PQerrorMessage(conn);
  }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

absl::StatusOr<std::unique_ptr<MotionPoller>> MotionPoller::Create(
    const std::string& db_connstr) {
  auto poller = std::unique_ptr<MotionPoller>(new MotionPoller());
  poller->impl_ = std::make_unique<Impl>();
  poller->impl_->conn = PQconnectdb(db_connstr.c_str());
  if (PQstatus(poller->impl_->conn) != CONNECTION_OK) {
    std::string err = PQerrorMessage(poller->impl_->conn);
    return absl::InternalError("MotionPoller: " + err);
  }
  return poller;
}

MotionPoller::~MotionPoller() { stop(); }

void MotionPoller::set_camera_ids(const std::vector<std::string>& ids) {
  impl_->camera_ids = ids;
}

void MotionPoller::set_camera_macs(
    const std::map<std::string, std::string>& id_to_mac) {
  impl_->id_to_mac = id_to_mac;
}

void MotionPoller::set_detector(
    const object_detect::ObjectDetector* detector) {
  impl_->detector = detector;
}

void MotionPoller::set_alarm_notifier(AlarmNotifier* notifier) {
  impl_->alarm_notifier = notifier;
}

void MotionPoller::set_ubv_dir(const std::string& dir) {
  impl_->ubv_dir = dir;
}

void MotionPoller::set_poll_interval(int sec) {
  impl_->poll_interval_sec = sec;
}

void MotionPoller::set_coalesce_window(uint32_t sec) {
  impl_->coalesce_window_sec = sec;
}

void MotionPoller::set_use_msr_thumbnail_ids(bool use_msr) {
  impl_->use_msr_thumb_ids = use_msr;
}

void MotionPoller::set_protect_api(const std::string& url,
                                   ProtectUserIdProvider* provider) {
  impl_->protect_url = url;
  impl_->protect_user_id_provider = provider;
}

void MotionPoller::start() {
  if (impl_->camera_ids.empty() || !impl_->detector) return;
  running_.store(true);
  thread_ = std::thread([this] { poll_loop(); });
}

void MotionPoller::stop() {
  running_.store(false);
  if (thread_.joinable()) thread_.join();
}

// ---------------------------------------------------------------------------
// High-water mark initialisation
// ---------------------------------------------------------------------------

void MotionPoller::init_high_water_marks() {
  const uint64_t default_hwm = util::now_ms() - 3600000ULL;  // 1 hour ago

  for (const auto& cam_id : impl_->camera_ids) {
    impl_->maybe_reconnect();
    const std::string def_str = std::to_string(default_hwm);
    const char* params[] = { def_str.c_str(), cam_id.c_str() };
    PGresult* res = PQexecParams(impl_->conn,
      "SELECT COALESCE(MAX(e.start), $1::bigint) "
      "FROM events e "
      "WHERE e.type = 'smartDetectZone' "
      "  AND e.\"cameraId\" = $2 "
      "  AND (e.metadata::jsonb->>'source') = 'onvif-recorder'",
      2, nullptr, params, nullptr, nullptr, 0);

    uint64_t hwm = default_hwm;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
      hwm = static_cast<uint64_t>(std::stoull(PQgetvalue(res, 0, 0)));
    PQclear(res);

    impl_->hwm[cam_id] = hwm;
    LOG(INFO) << "[motion_poller] camera " << cam_id
              << " high-water mark: " << hwm;
  }
}

// ---------------------------------------------------------------------------
// Main poll loop
// ---------------------------------------------------------------------------

// Log the recent event-type distribution for every watched camera.
// Used at startup and periodically so a journal capture immediately
// shows whether each camera is producing the `motion` events the poller
// looks for, vs `smartDetectZone` (already-classified) or nothing at all.
void MotionPoller::log_event_type_breakdown(const char* label) {
  const uint64_t since_ms = util::now_ms() - 3600000ULL;  // last hour
  const std::string since_str = std::to_string(since_ms);
  for (const auto& cam_id : impl_->camera_ids) {
    impl_->maybe_reconnect();
    const char* params[] = { cam_id.c_str(), since_str.c_str() };
    PGresult* res = PQexecParams(impl_->conn,
      "SELECT type, COUNT(*) FROM events "
      "WHERE \"cameraId\" = $1 AND start > $2::bigint "
      "GROUP BY type ORDER BY 2 DESC",
      2, nullptr, params, nullptr, nullptr, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
      PQclear(res);
      continue;
    }
    std::string summary;
    const int n = PQntuples(res);
    for (int i = 0; i < n; ++i) {
      if (i > 0) summary += ' ';
      summary += PQgetvalue(res, i, 0);
      summary += '=';
      summary += PQgetvalue(res, i, 1);
    }
    PQclear(res);
    if (summary.empty()) summary = "(no events in last 1h)";
    LOG(INFO) << "[motion_poller] " << label << " camera " << cam_id
              << " last 1h: " << summary;
  }
}

void MotionPoller::poll_loop() {
  LOG(INFO) << "[motion_poller] started, watching "
            << impl_->camera_ids.size() << " camera(s), interval "
            << impl_->poll_interval_sec << "s";

  // (A) Detector readiness.  start() already returns early when the
  // detector is null, but log explicitly so the journal makes it
  // unambiguous what classifier (if any) the poller will run.
  if (impl_->detector != nullptr) {
    LOG(INFO) << "[motion_poller] detector ready: NanoDet-M loaded";
  } else {
    LOG(WARNING) << "[motion_poller] detector is null; motion events "
                 << "will not be classified";
  }

  init_high_water_marks();

  // (B) Per-camera event-type breakdown at startup.  Tells us
  // immediately whether the cameras are emitting `motion` (what the
  // poller looks for) or `smartDetectZone` directly (native AI) or
  // nothing at all -- a frequent source of "first-party not classified"
  // confusion.
  log_event_type_breakdown("startup");

  // (C) Periodic heartbeat: aggregate counts across the last
  // kHeartbeatEveryPolls polls and emit a single line summary.
  // (B) Periodic event-type breakdown: same query as startup, every
  // kBreakdownEveryPolls polls.
  constexpr int kHeartbeatEveryPolls = 5;
  constexpr int kBreakdownEveryPolls = 180;  // ~30 min at 10s interval
  int polls_since_heartbeat = 0;
  int polls_since_breakdown = 0;
  uint64_t hb_candidates = 0;
  uint64_t hb_classified = 0;
  uint64_t hb_skipped_no_thumb = 0;
  uint64_t hb_skipped_overlap = 0;

  while (running_.load()) {
    impl_->maybe_reconnect();

    // Per-camera poll: each camera gets its own hwm-bounded query.
    // Earlier versions used a single global query parameterised by
    // MIN(per-camera hwm), but that caused a livelock — inactive
    // cameras held the global min back, the LIMIT-50 window filled
    // with already-processed events from active cameras, and newer
    // events never reached the loop.  Querying per camera removes
    // that head-of-line blocking entirely.
    for (const std::string& cam_id : impl_->camera_ids) {
      if (!running_.load()) break;
      impl_->maybe_reconnect();

      auto hwm_it = impl_->hwm.find(cam_id);
      const uint64_t cam_hwm = (hwm_it != impl_->hwm.end())
          ? hwm_it->second : (util::now_ms() - 3600000ULL);
      const std::string hwm_str = std::to_string(cam_hwm);
      const char* params[] = { cam_id.c_str(), hwm_str.c_str() };

      // (D) Count motion events in the same window that WOULD have
      // matched but were excluded by the NOT EXISTS smartDetectZone
      // filter.  Lets the journal show "we had candidates but Protect
      // already classified them" -- otherwise they're invisible.
      {
        PGresult* res_d = PQexecParams(impl_->conn,
          "SELECT COUNT(*) FROM events e "
          "WHERE e.type = 'motion' "
          "  AND e.\"cameraId\" = $1 "
          "  AND e.start > $2::bigint "
          "  AND e.\"thumbnailId\" IS NOT NULL "
          "  AND e.\"end\" IS NOT NULL "
          "  AND EXISTS ( "
          "    SELECT 1 FROM events e2 "
          "    WHERE e2.type = 'smartDetectZone' "
          "      AND e2.\"cameraId\" = e.\"cameraId\" "
          "      AND e2.start >= e.start - 5000 "
          "      AND e2.start <= e.\"end\" + 5000 "
          "  )",
          2, nullptr, params, nullptr, nullptr, 0);
        if (PQresultStatus(res_d) == PGRES_TUPLES_OK &&
            PQntuples(res_d) > 0) {
          uint64_t n = static_cast<uint64_t>(
              std::stoull(PQgetvalue(res_d, 0, 0)));
          hb_skipped_overlap += n;
        }
        PQclear(res_d);
      }

      PGresult* res = PQexecParams(impl_->conn,
        "SELECT e.id, e.start, e.\"end\", e.\"cameraId\", e.\"thumbnailId\" "
        "FROM events e "
        "WHERE e.type = 'motion' "
        "  AND e.\"cameraId\" = $1 "
        "  AND e.start > $2::bigint "
        "  AND e.\"thumbnailId\" IS NOT NULL "
        "  AND e.\"end\" IS NOT NULL "
        "  AND NOT EXISTS ( "
        "    SELECT 1 FROM events e2 "
        "    WHERE e2.type = 'smartDetectZone' "
        "      AND e2.\"cameraId\" = e.\"cameraId\" "
        "      AND e2.start >= e.start - 5000 "
        "      AND e2.start <= e.\"end\" + 5000 "
        "  ) "
        "ORDER BY e.start ASC LIMIT 50",
        2, nullptr, params, nullptr, nullptr, 0);

      if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        LOG(ERROR) << "[motion_poller] poll query failed (camera "
                   << cam_id << "): " << PQerrorMessage(impl_->conn);
        PQclear(res);
        continue;
      }

      const int nrows = PQntuples(res);
      hb_candidates += static_cast<uint64_t>(nrows);
      if (nrows > 0)
        LOG(INFO) << "[motion_poller] poll returned " << nrows
                  << " motion event(s) to process for camera " << cam_id;
      for (int i = 0; i < nrows && running_.load(); ++i) {
        const std::string ev_id      = PQgetvalue(res, i, 0);
        const uint64_t    start_ms   =
            static_cast<uint64_t>(std::stoull(PQgetvalue(res, i, 1)));
        const uint64_t    end_ms     =
            static_cast<uint64_t>(std::stoull(PQgetvalue(res, i, 2)));
        // cameraId column is redundant (it always matches cam_id from
        // the outer loop), but keeping it makes the row tuple uniform
        // with the prior global-query layout — useful when grepping
        // dumps that span versions.
        (void)PQgetvalue(res, i, 3);
        const std::string thumb_id   = PQgetvalue(res, i, 4);

        LOG(INFO) << "[motion_poller] processing motion event " << ev_id
                  << " camera=" << cam_id << " thumb=" << thumb_id
                  << " start=" << start_ms << " end=" << end_ms;

        // Fetch the thumbnail JPEG.  Protect routes thumbnailIds by
        // length: 24-char IDs live in the `thumbnails` Postgres table;
        // any other length (typically the MSR "{MAC}-{ts}" 26-char
        // form Protect uses for native first-party cameras post 7.x)
        // is stored as a UBV file served by the msp media server.
        // Try the DB first for 24-char IDs; for the rest, hit the
        // local Protect API which routes to msp transparently.
        std::vector<uint8_t> jpeg;
        if (thumb_id.size() == 24) {
          impl_->maybe_reconnect();
          const char* tp[] = { thumb_id.c_str() };
          PGresult* thumb_res = PQexecParams(impl_->conn,
            "SELECT content FROM thumbnails WHERE id = $1",
            1, nullptr, tp, nullptr, nullptr, 1);

          if (PQresultStatus(thumb_res) == PGRES_TUPLES_OK &&
              PQntuples(thumb_res) > 0 &&
              !PQgetisnull(thumb_res, 0, 0)) {
            const char* raw = PQgetvalue(thumb_res, 0, 0);
            const int raw_len = PQgetlength(thumb_res, 0, 0);
            jpeg.assign(raw, raw + raw_len);
          }
          PQclear(thumb_res);
        } else if (!impl_->protect_url.empty() &&
                   impl_->protect_user_id_provider &&
                   !impl_->protect_user_id_provider->empty()) {
          // Non-24-char ID: msp-served UBV thumbnail.  Fetch via
          // Protect's local /api/thumbnails/<id> which dispatches to
          // msp and returns the JPEG bytes back to us.  401 -> the
          // provider re-discovers the user_id and we retry once.
          jpeg = fetch_thumbnail_via_protect(
              impl_->protect_url, impl_->protect_user_id_provider, thumb_id);
        }

        if (jpeg.empty()) {
          LOG(INFO) << "[motion_poller] skip event " << ev_id
                    << ": thumbnail " << thumb_id
                    << (thumb_id.size() == 24
                            ? " not in DB"
                            : " not reachable via Protect API");
          ++hb_skipped_no_thumb;
          // Update hwm even on skip so we don't retry endlessly.
          impl_->hwm[cam_id] = start_ms;
          continue;
        }

        LOG(INFO) << "[motion_poller] event " << ev_id
                  << ": fetched thumbnail " << thumb_id
                  << " (" << jpeg.size() << " bytes), running NanoDet-M";

        // Run NanoDet-M on the thumbnail.
        auto det = impl_->detector->detect(jpeg);
        if (!det.has_value()) {
          LOG(INFO) << "[motion_poller] skip event " << ev_id
                    << ": NanoDet-M returned no detection"
                    << " (no object above confidence threshold)";
          impl_->hwm[cam_id] = start_ms;
          continue;
        }
        if (!object_detect::is_security_relevant(det->class_id)) {
          LOG(INFO) << "[motion_poller] skip event " << ev_id
                    << ": NanoDet-M detected class_id=" << det->class_id
                    << " which is not security-relevant"
                    << " (person/vehicle/animal/package)";
          impl_->hwm[cam_id] = start_ms;
          continue;
        }

        // NanoDet-M reports confidence in [0, 1].  UniFi Protect's
        // events.score / smartDetectObjects.attributes.confidence
        // schema uses an integer in [0, 100], so scale + clamp here
        // and reuse for both the SQL parameter and the in-row JSON
        // blobs we build below.
        const int confidence = std::max(0, std::min(100,
            static_cast<int>(std::lround(det->confidence * 100.0f))));
        const std::string conf_str = std::to_string(confidence);
        const std::string obj_type =
            object_detect::detection_type(det->class_id);
        const std::string sdt_json =
            motion_poller_internal::smart_detect_types_json(obj_type);
        const std::string new_event_id = util::generate_uuid();
        const std::string sdo_id       = util::generate_uuid();
        const std::string sdr_id       = util::generate_uuid();
        // Resolve MAC for MSR-format thumbnail IDs and UBV writing.
        std::string cam_mac;
        {
          auto mac_it = impl_->id_to_mac.find(cam_id);
          if (mac_it != impl_->id_to_mac.end())
            cam_mac = mac_it->second;
        }
        const std::string new_thumb_id =
            (impl_->use_msr_thumb_ids && !cam_mac.empty())
                ? util::make_msr_thumbnail_id(cam_mac, start_ms)
                : util::generate_24hex_id();
        const std::string now_str      = util::utc_now_iso8601();
        const std::string start_str    = std::to_string(start_ms);
        const std::string end_str      = std::to_string(end_ms);
        const std::string ts_str       = std::to_string(start_ms);

        // Crop the thumbnail using the detection bbox.
        std::vector<uint8_t> cropped = jpeg_crop::crop(jpeg, det->bbox);
        if (cropped.empty()) cropped = std::move(jpeg);

        // INSERT event.
        {
          const char* ep[] = {
            new_event_id.c_str(), start_str.c_str(), cam_id.c_str(),
            sdt_json.c_str(), new_thumb_id.c_str(),
            now_str.c_str(), now_str.c_str(), end_str.c_str(),
            conf_str.c_str()
          };
          impl_->maybe_reconnect();
          PGresult* r = PQexecParams(impl_->conn,
            "INSERT INTO events"
            " (id, type, start, \"cameraId\", score, \"smartDetectTypes\","
            "  metadata, locked, \"thumbnailId\", \"createdAt\","
            "  \"updatedAt\", \"end\")"
            " VALUES ($1, 'smartDetectZone', $2::bigint, $3, $9::int, "
            "  $4::json, '{\"source\":\"onvif-recorder\"}'::json, false, $5,"
            "  $6, $7, $8::bigint)",
            9, nullptr, ep, nullptr, nullptr, 0);
          if (PQresultStatus(r) != PGRES_COMMAND_OK)
            LOG(ERROR) << "[motion_poller] insert event: "
                       << PQerrorMessage(impl_->conn);
          PQclear(r);
        }

        // INSERT smartDetectObjects.
        {
          const std::string attr_json =
              motion_poller_internal::build_sdo_attributes(
                  obj_type, confidence);
          const char* sp[] = {
            sdo_id.c_str(), new_event_id.c_str(), new_thumb_id.c_str(),
            cam_id.c_str(), obj_type.c_str(), attr_json.c_str(),
            ts_str.c_str(), now_str.c_str(), now_str.c_str()
          };
          PGresult* r = PQexecParams(impl_->conn,
            "INSERT INTO \"smartDetectObjects\""
            " (id, \"eventId\", \"thumbnailId\", \"cameraId\", type,"
            "  attributes, \"detectedAt\", metadata,"
            "  \"createdAt\", \"updatedAt\")"
            " VALUES ($1, $2, $3, $4, $5, $6::json, $7::bigint,"
            "  '{}'::jsonb, $8, $9)",
            9, nullptr, sp, nullptr, nullptr, 0);
          if (PQresultStatus(r) != PGRES_COMMAND_OK)
            LOG(ERROR) << "[motion_poller] insert sdo: "
                       << PQerrorMessage(impl_->conn);
          PQclear(r);
        }

        // INSERT smartDetectTracks.  Required for the iOS app's Find
        // Anything filter to surface our events alongside native ones.
        {
          const std::string sdtrk_id      = util::generate_uuid();
          const std::string sdtrk_payload =
              motion_poller_internal::build_sdt_payload(
                  start_ms, end_ms, obj_type, confidence);
          const char* tp[] = {
            sdtrk_id.c_str(), new_event_id.c_str(), cam_id.c_str(),
            sdtrk_payload.c_str(), now_str.c_str(), now_str.c_str()
          };
          PGresult* r = PQexecParams(impl_->conn,
            "INSERT INTO \"smartDetectTracks\""
            " (id, \"eventId\", \"cameraId\", payload,"
            "  \"createdAt\", \"updatedAt\")"
            " VALUES ($1, $2, $3, $4::json, $5, $6)",
            6, nullptr, tp, nullptr, nullptr, 0);
          if (PQresultStatus(r) != PGRES_COMMAND_OK)
            LOG(ERROR) << "[motion_poller] insert sdt: "
                       << PQerrorMessage(impl_->conn);
          PQclear(r);
        }

        // INSERT smartDetectRaws.
        {
          const std::string payload =
              motion_poller_internal::build_sdr_payload(
                  start_ms, obj_type, confidence);
          const char* rp[] = {
            sdr_id.c_str(), cam_id.c_str(), payload.c_str(),
            ts_str.c_str(), now_str.c_str(), now_str.c_str()
          };
          PGresult* r = PQexecParams(impl_->conn,
            "INSERT INTO \"smartDetectRaws\""
            " (id, \"cameraId\", payload, timestamp,"
            "  \"createdAt\", \"updatedAt\")"
            " VALUES ($1, $2, $3::json, $4::bigint, $5, $6)",
            6, nullptr, rp, nullptr, nullptr, 0);
          if (PQresultStatus(r) != PGRES_COMMAND_OK)
            LOG(ERROR) << "[motion_poller] insert sdr: "
                       << PQerrorMessage(impl_->conn);
          PQclear(r);
        }

        // INSERT thumbnail (cropped JPEG).
        {
          const int jpeg_len = static_cast<int>(cropped.size());
          const char* jpeg_ptr = reinterpret_cast<const char*>(cropped.data());
          const char* tp2[] = {
            new_thumb_id.c_str(), cam_id.c_str(), new_event_id.c_str(),
            ts_str.c_str(), now_str.c_str(), now_str.c_str(), jpeg_ptr
          };
          const int lengths[] = { 0, 0, 0, 0, 0, 0, jpeg_len };
          const int formats[] = { 0, 0, 0, 0, 0, 0, 1 };  // last = binary
          PGresult* r = PQexecParams(impl_->conn,
            "INSERT INTO thumbnails"
            " (id, \"cameraId\", \"eventId\", timestamp,"
            "  \"createdAt\", \"updatedAt\", content, \"isFullfov\")"
            " VALUES ($1, $2, $3, $4::bigint, $5, $6, $7, false)"
            " ON CONFLICT (id) DO NOTHING",
            7, nullptr, tp2, lengths, formats, 0);
          if (PQresultStatus(r) != PGRES_COMMAND_OK)
            LOG(ERROR) << "[motion_poller] insert thumbnail: "
                       << PQerrorMessage(impl_->conn);
          PQclear(r);
        }

        // Write UBV thumbnail file (native Protect path).
        if (!impl_->ubv_dir.empty() && !cam_mac.empty()) {
          {
            const std::string& mac = cam_mac;
            std::time_t tsec = static_cast<std::time_t>(start_ms / 1000);
            std::tm ttm{};
            gmtime_r(&tsec, &ttm);
            char dbuf[16];
            std::strftime(dbuf, sizeof(dbuf), "%Y/%m/%d", &ttm);
            std::string dstr(dbuf);

            auto& cached = impl_->ubv_cache[mac];
            if (cached.first != dstr) {
              cached.first = dstr;
              cached.second = ubv::protect_path(impl_->ubv_dir, mac, start_ms);
            }
            auto us = ubv::append(cached.second, {start_ms, cropped});
            if (!us.ok())
              LOG(WARNING) << "[motion_poller] ubv append: " << us.message();
          }
        }

        // Fire alarm notification.
        if (impl_->alarm_notifier && !cam_mac.empty()) {
          impl_->alarm_notifier->notify(obj_type, cam_mac,
                                        new_event_id, start_ms);
        }

        LOG(INFO) << "[motion_poller] " << obj_type << " detected in "
                  << cam_id << " (motion event " << ev_id << ")";

        ++hb_classified;
        // Update high-water mark.
        impl_->hwm[cam_id] = start_ms;
      }

      PQclear(res);
    }  // end per-camera loop


    // (C) Heartbeat: every kHeartbeatEveryPolls cycles, summarise what
    // happened.  Always fires even when the pipeline is idle so the
    // journal makes "the poller is alive but nothing matched" obvious.
    if (++polls_since_heartbeat >= kHeartbeatEveryPolls) {
      uint64_t min_hwm_log = UINT64_MAX;
      for (const auto& [id, h] : impl_->hwm)
        if (h < min_hwm_log) min_hwm_log = h;
      LOG(INFO) << "[motion_poller] heartbeat: " << kHeartbeatEveryPolls
                << " polls, " << hb_candidates << " candidates, "
                << hb_classified << " classified, "
                << hb_skipped_no_thumb << " skipped(no_thumb), "
                << hb_skipped_overlap
                << " excluded(already smartDetectZone), hwm-min="
                << (min_hwm_log == UINT64_MAX ? 0 : min_hwm_log);
      polls_since_heartbeat = 0;
      hb_candidates = 0;
      hb_classified = 0;
      hb_skipped_no_thumb = 0;
      hb_skipped_overlap = 0;
    }

    // (B) Periodic event-type breakdown so a long-running journal still
    // carries fresh visibility into what each camera is producing.
    if (++polls_since_breakdown >= kBreakdownEveryPolls) {
      log_event_type_breakdown("periodic");
      polls_since_breakdown = 0;
    }

    // Sleep in short increments so stop() is responsive.
    for (int s = 0; s < impl_->poll_interval_sec && running_.load(); ++s)
      std::this_thread::sleep_for(std::chrono::seconds(1));
  }

  LOG(INFO) << "[motion_poller] stopped";
}

}  // namespace onvif
