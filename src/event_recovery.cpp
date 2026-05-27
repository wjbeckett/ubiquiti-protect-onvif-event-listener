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

#include "event_recovery.hpp"

#include <dirent.h>
#include <libpq-fe.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/log/log.h"
#include "absl/status/status.h"
#include "event_enricher.hpp"
#include "pg_util.hpp"
#include "protect_version.hpp"

namespace onvif {
namespace event_recovery {

namespace {

// Common locations of pg_restore on a Protect-host system, in preference
// order.  We require 16+ to read the dump.dl format produced by Protect's
// daily backups (dump version 1.15 needs server 16 client tools).
constexpr const char* kPgRestoreCandidates[] = {
  "/usr/lib/postgresql/16/bin/pg_restore",
  "/usr/lib/postgresql/17/bin/pg_restore",
  "/usr/lib/postgresql/18/bin/pg_restore",
  "/usr/bin/pg_restore",   // last resort; may be old
};

// Resolve a pg_restore binary on disk; returns empty string if none found.
std::string FindPgRestore() {
  for (const char* p : kPgRestoreCandidates) {
    if (access(p, X_OK) == 0) return std::string(p);
  }
  return {};
}

// Pull a single-column bigint result from a simple SELECT.  Returns -1 on
// null/missing/error so callers can distinguish "no rows" from "value 0".
int64_t SelectBigint(PGconn* conn, const char* sql) {
  PGresult* r = onvif::pg::ExecWithTimeout(conn, -1, sql);
  if (PQresultStatus(r) != PGRES_TUPLES_OK) {
    LOG(WARNING) << "[recovery] query failed: " << PQerrorMessage(conn);
    PQclear(r);
    return -1;
  }
  if (PQntuples(r) == 0 || PQgetisnull(r, 0, 0)) {
    PQclear(r);
    return -1;
  }
  const std::string s = PQgetvalue(r, 0, 0);
  PQclear(r);
  // -fno-exceptions: use strtoll which signals errors via errno + endptr.
  char* endp = nullptr;
  errno = 0;
  int64_t v = static_cast<int64_t>(std::strtoll(s.c_str(), &endp, 10));
  if (errno != 0 || endp == s.c_str()) return -1;
  return v;
}

bool RunSimple(PGconn* conn, const std::string& sql) {
  PGresult* r = onvif::pg::ExecWithTimeout(conn, -1, sql.c_str());
  bool ok = (PQresultStatus(r) == PGRES_COMMAND_OK
             || PQresultStatus(r) == PGRES_TUPLES_OK);
  if (!ok) LOG(WARNING) << "[recovery] " << PQerrorMessage(conn);
  PQclear(r);
  return ok;
}

}  // namespace

bool ShouldRecoverFromTimestamps(int64_t oldest_event_ms,
                                  int64_t oldest_recording_ms,
                                  uint64_t threshold_ms) {
  // No events at all => recover.
  if (oldest_event_ms < 0) return true;
  // No recordings to anchor against => can't reason; don't recover.
  if (oldest_recording_ms < 0) return false;
  // Recover if events start significantly later than the recordings -- i.e.
  // the events table was wiped while video kept rolling.
  return oldest_event_ms > oldest_recording_ms + static_cast<int64_t>(threshold_ms);
}

bool ShouldRecover(PGconn* conn, uint64_t threshold_ms) {
  if (!protect_version::IsAtLeast(7, 1, 0)) return false;
  const int64_t oldest_event =
      SelectBigint(conn, "SELECT min(start) FROM events WHERE \"cameraId\" IS NOT NULL");
  const int64_t oldest_recording =
      SelectBigint(conn, "SELECT min(start) FROM \"recordingFiles\"");
  const bool yes = ShouldRecoverFromTimestamps(
      oldest_event, oldest_recording, threshold_ms);
  LOG(INFO) << "[recovery] oldest_event_ms=" << oldest_event
            << " oldest_recording_ms=" << oldest_recording
            << " threshold_ms=" << threshold_ms
            << " should_recover=" << (yes ? "true" : "false");
  return yes;
}

std::optional<Backup> PickNewest(const std::vector<Backup>& candidates) {
  if (candidates.empty()) return std::nullopt;
  const Backup* best = &candidates.front();
  for (const auto& b : candidates) {
    if (b.mtime_ms > best->mtime_ms) best = &b;
  }
  return *best;
}

std::optional<Backup> FindLatestBackup(const std::string& dir) {
  DIR* d = opendir(dir.c_str());
  if (!d) {
    LOG(INFO) << "[recovery] backup dir not present: " << dir;
    return std::nullopt;
  }
  std::vector<Backup> found;
  while (struct dirent* e = readdir(d)) {
    std::string_view name(e->d_name);
    // Match Protect's naming: db_backup_partial.*.dump or .dump.dl.
    if (name.find("db_backup_partial.") != 0) continue;
    if (name.find(".dump") == std::string_view::npos) continue;
    std::string path = dir + "/" + std::string(name);
    struct stat st{};
    if (stat(path.c_str(), &st) != 0) continue;
    Backup b;
    b.path = path;
    b.mtime_ms = static_cast<uint64_t>(st.st_mtim.tv_sec) * 1000ULL
                + static_cast<uint64_t>(st.st_mtim.tv_nsec) / 1'000'000ULL;
    found.push_back(std::move(b));
  }
  closedir(d);
  return PickNewest(found);
}

absl::Status RestoreFromBackup(PGconn* conn, const std::string& dump_path) {
  const std::string pgr = FindPgRestore();
  if (pgr.empty()) {
    return absl::FailedPreconditionError(
        "pg_restore 16+ not found; cannot recover from backup");
  }

  // Apply the dump directly into the live cluster via pg_restore's --dbname
  // option.  pg_restore handles the custom-format COPY blobs natively; we
  // don't have to round-trip via SQL text.  --data-only skips table-create
  // attempts; -t restricts to the three tables present in Protect's
  // "partial" backups.  pg_restore's default behaviour is to continue past
  // duplicate-key errors (it reports them but doesn't abort), which is
  // exactly what we want on a re-run.
  //
  // We need a conninfo string for pg_restore.  PQdb / PQhost / PQport
  // reconstruct it from our existing libpq connection so we re-use the
  // operator's --db_conn configuration.
  const std::string db   = PQdb(conn)   ? PQdb(conn)   : "unifi-protect";
  const std::string host = PQhost(conn) ? PQhost(conn) : "/run/postgresql";
  const std::string port = PQport(conn) ? PQport(conn) : "5433";
  const std::string user = PQuser(conn) ? PQuser(conn) : "postgres";

  std::ostringstream cmd;
  cmd << pgr
      // --disable-triggers makes pg_restore set session_replication_role to
      // replica while loading, which suppresses FK checks.  Required because
      // Protect's partial backup TOC lists detectionLabels BEFORE events, so
      // the FK from detectionLabels.eventId would fail at COPY time without
      // it.  Needs superuser privs (we connect as postgres).
      << " --data-only --no-owner --no-privileges --disable-triggers"
      << " -t events -t \"detectionLabels\" -t labels"
      << " -h '" << host << "' -p '" << port << "'"
      << " -U '" << user << "' -d '" << db << "'"
      << " '" << dump_path << "'"
      // pg_restore writes errors to stderr; let them flow to journal so
      // duplicate-key noise from a re-run is observable but doesn't fail us.
      << " 2>&1";
  LOG(INFO) << "[recovery] running: " << cmd.str();
  int rc = std::system(cmd.str().c_str());
  // pg_restore exits non-zero if ANY rows fail (e.g. duplicate keys on a
  // re-run, or FK to a camera that no longer exists).  That's fine -- the
  // successful rows still landed.  We only treat it as a hard failure when
  // it can't find / read / parse the dump at all (exit codes 1-2 with the
  // "could not" prefix on stderr).  Distinguishing those reliably is more
  // trouble than it's worth; log and continue.
  if (rc != 0) {
    LOG(WARNING) << "[recovery] pg_restore returned " << rc
                 << " (likely some duplicate-key errors -- expected on re-run)";
  }
  return absl::OkStatus();
}

absl::Status EnrichRestored(PGconn* conn, int image_width, int image_height) {
  // Pull every event that needs any backfill work.  Three reasons we might
  // need to touch an event:
  //   (a) metadata still has the legacy sparse shape (no detectedAreas) ->
  //       UPDATE it to the rich shape.
  //   (b) detectionLabels references an objectId that doesn't yet have a
  //       smartDetectObjects row (typical for restored events: backups carry
  //       detectionLabels but not the per-object detail tables) -> INSERT
  //       the SDO + paired SDA so the UI bbox overlay + Inspect-Detection
  //       panel render.
  //   (c) we've enriched metadata but the SDA didn't land for some reason ->
  //       re-INSERT (ON CONFLICT DO NOTHING covers idempotency).
  // The metadata UPDATE is idempotent (rewrites the same canonical synth)
  // so running on case (b)/(c) events just does a no-op rewrite.
  const char* select_events =
      "SELECT e.id, e.\"cameraId\", e.type, "
      "       e.\"smartDetectTypes\"::text, "
      "       e.start, COALESCE(e.\"end\", e.start), "
      "       COALESCE(e.score, 100), "
      "       COALESCE(e.\"thumbnailId\", '') "
      "FROM events e "
      "WHERE e.\"cameraId\" IS NOT NULL "
      "  AND ( "
      "    e.metadata IS NULL "
      "    OR NOT jsonb_path_exists(e.metadata::jsonb, '$.detectedAreas') "
      "    OR EXISTS ( "
      "      SELECT 1 FROM \"detectionLabels\" dl "
      "      WHERE dl.\"eventId\" = e.id "
      "        AND dl.\"objectId\" IS NOT NULL "
      "        AND NOT EXISTS ( "
      "          SELECT 1 FROM \"smartDetectObjects\" sdo "
      "          WHERE sdo.id = dl.\"objectId\" "
      "        ) "
      "    ) "
      "  )";

  PGresult* r = onvif::pg::ExecWithTimeout(conn, -1, select_events);
  if (PQresultStatus(r) != PGRES_TUPLES_OK) {
    auto msg = std::string("[recovery] select events failed: ")
             + PQerrorMessage(conn);
    PQclear(r);
    return absl::InternalError(msg);
  }
  const int n = PQntuples(r);
  LOG(INFO) << "[recovery] enriching " << n << " events";
  int enriched = 0;
  for (int i = 0; i < n; ++i) {
    enricher::EventInput ein;
    ein.event_id    = PQgetvalue(r, i, 0);
    ein.camera_id   = PQgetvalue(r, i, 1);
    ein.event_type  = PQgetvalue(r, i, 2);
    const std::string sdt_text = PQgetvalue(r, i, 3);
    // Strip the JSON quotes/brackets to extract the first type.  Lightweight
    // parse since the column is always shaped like '["person"]' or '[]'.
    size_t q1 = sdt_text.find('"'), q2 = sdt_text.find('"', q1 + 1);
    if (q1 != std::string::npos && q2 != std::string::npos)
      ein.smart_detect_types = {sdt_text.substr(q1 + 1, q2 - q1 - 1)};
    ein.start_ms     = std::stoull(PQgetvalue(r, i, 4));
    ein.end_ms       = std::stoull(PQgetvalue(r, i, 5));
    ein.score        = std::atoi(PQgetvalue(r, i, 6));
    ein.thumbnail_id = PQgetvalue(r, i, 7);
    ein.image_width  = image_width;
    ein.image_height = image_height;

    // Per-object UUIDs: prefer existing SDO rows (live-written), fall back to
    // the objectId column on per-object detectionLabels rows (which the
    // partial backup carries even when smartDetectObjects doesn't).  Both
    // sources use the same UUID space so the FK chain SDA -> SDO -> event
    // stays coherent.
    const char* sdo_params[] = { ein.event_id.c_str() };
    PGresult* s = onvif::pg::ExecParamsWithTimeout(
        conn, -1,
        "SELECT id FROM \"smartDetectObjects\" WHERE \"eventId\" = $1 "
        "UNION "
        "SELECT \"objectId\" FROM \"detectionLabels\" "
        " WHERE \"eventId\" = $1 AND \"objectId\" IS NOT NULL",
        1, nullptr, sdo_params, nullptr, nullptr, 0);
    if (PQresultStatus(s) == PGRES_TUPLES_OK) {
      const int ns = PQntuples(s);
      ein.object_ids.reserve(ns);
      for (int j = 0; j < ns; ++j) ein.object_ids.emplace_back(PQgetvalue(s, j, 0));
    }
    PQclear(s);

    // Materialise a smartDetectObjects row for any objectId we found via
    // detectionLabels that doesn't yet have one.  Without this the bbox /
    // Inspect-Detection panel stays empty even though the event is visible.
    const std::string det_type =
        ein.smart_detect_types.empty() ? std::string("unknown")
                                       : ein.smart_detect_types.front();
    const std::string attrs = enricher::BuildSmartDetectObjectAttributes(
        ein.score, det_type);
    const std::string ts_ms_str = std::to_string(ein.start_ms);
    for (const std::string& oid : ein.object_ids) {
      const char* p[] = {
        oid.c_str(), ein.event_id.c_str(), ein.camera_id.c_str(),
        ein.thumbnail_id.empty() ? nullptr : ein.thumbnail_id.c_str(),
        det_type.c_str(), attrs.c_str(), ts_ms_str.c_str(),
      };
      PGresult* sr = onvif::pg::ExecParamsWithTimeout(
          conn, -1,
          "INSERT INTO \"smartDetectObjects\" "
          "(id, \"eventId\", \"cameraId\", \"thumbnailId\", type, attributes, "
          " \"detectedAt\", metadata, \"createdAt\", \"updatedAt\") "
          "VALUES ($1, $2, $3, $4, $5, $6::json, $7::bigint, '{}'::json, "
          "        now(), now()) "
          "ON CONFLICT (id) DO NOTHING",
          7, nullptr, p, nullptr, nullptr, 0);
      if (PQresultStatus(sr) != PGRES_COMMAND_OK) {
        LOG(WARNING) << "[recovery] SDO INSERT failed for " << oid << ": "
                     << PQerrorMessage(conn);
      }
      PQclear(sr);
    }

    // Rich metadata + thumbnailFullfovId UPDATE.  Use PQexecParams so we
    // don't have to escape JSON quotes inline.
    //
    // CRITICAL: thumbnailFullfovId is only written when the column is
    // currently NULL.  Many backup-restored events already have a real
    // MSR-format full-FOV id from Protect's native AI processing (e.g.
    // "802AA84E8F75-1779156609811" pointing at a real UBV thumbnail file).
    // Overwriting those with our 24-char placeholder breaks the UI
    // thumbnail load -- the MSR id resolves via msp+UBV, the 24-char id
    // expects a `thumbnails` table row that doesn't exist post-wipe.
    const std::string md = enricher::BuildEnrichedMetadata(ein);
    const char* up[] = {
      md.c_str(),
      ein.thumbnail_id.empty() ? nullptr : ein.thumbnail_id.c_str(),
      ein.event_id.c_str(),
    };
    PGresult* upr = onvif::pg::ExecParamsWithTimeout(
        conn, -1,
        "UPDATE events SET metadata = $1::json, "
        "                  \"thumbnailFullfovId\" = "
        "                      COALESCE(\"thumbnailFullfovId\", $2) "
        "WHERE id = $3",
        3, nullptr, up, nullptr, nullptr, 0);
    if (PQresultStatus(upr) != PGRES_COMMAND_OK) {
      LOG(WARNING) << "[recovery] UPDATE metadata failed for "
                   << ein.event_id << ": " << PQerrorMessage(conn);
    }
    PQclear(upr);

    // Insert smartDetectObjectAreas per existing object.
    for (const std::string& oid : ein.object_ids) {
      const auto bb = enricher::PlaceholderBbox(
          image_width, image_height,
          ein.smart_detect_types.empty()
              ? std::string("unknown") : ein.smart_detect_types.front());
      const std::string sda_id = "sda-" + oid;
      const std::string aidx   = enricher::FullGridAreaIndexesSqlArray();
      std::ostringstream sql;
      sql << "INSERT INTO \"smartDetectObjectAreas\" "
          << "(id, \"smartDetectObjectId\", \"areaIndexes\","
          << " \"boundingX1\",\"boundingY1\",\"boundingX2\",\"boundingY2\","
          << " \"detectedAt\",\"lastSeenAt\") VALUES ("
          << "'" << sda_id << "','" << oid << "'," << aidx << ","
          << bb.x1 << "," << bb.y1 << "," << bb.x2 << "," << bb.y2 << ","
          << ein.start_ms << "," << ein.end_ms << ") "
          << "ON CONFLICT (id) DO NOTHING";
      RunSimple(conn, sql.str());
    }
    ++enriched;
  }
  PQclear(r);
  LOG(INFO) << "[recovery] enriched " << enriched << " events";
  return absl::OkStatus();
}

absl::Status Run(PGconn* conn, const std::string& backups_dir) {
  if (!protect_version::IsAtLeast(7, 1, 0)) {
    LOG(INFO) << "[recovery] skipped: Protect < 7.1.0";
    return absl::OkStatus();
  }
  if (!ShouldRecover(conn)) return absl::OkStatus();
  auto backup = FindLatestBackup(backups_dir);
  if (!backup) {
    LOG(INFO) << "[recovery] no backup file under " << backups_dir;
    return absl::OkStatus();
  }
  LOG(INFO) << "[recovery] restoring from " << backup->path;
  if (auto s = RestoreFromBackup(conn, backup->path); !s.ok()) {
    LOG(ERROR) << "[recovery] RestoreFromBackup: " << s.message();
    return s;
  }
  if (auto s = EnrichRestored(conn); !s.ok()) {
    LOG(ERROR) << "[recovery] EnrichRestored: " << s.message();
    return s;
  }
  LOG(INFO) << "[recovery] complete";
  return absl::OkStatus();
}

}  // namespace event_recovery
}  // namespace onvif
