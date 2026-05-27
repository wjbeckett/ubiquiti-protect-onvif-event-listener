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

// enrich_events -- standalone binary that translates sparse onvif-recorder
// event rows into the rich Protect 7.1+ shape (events.metadata enrichment,
// smartDetectObjects + smartDetectObjectAreas materialisation).
//
// Mirrors tools/enrich_restored_events.py.  Two input modes:
//   --from-db (default off, future default): live Protect Postgres
//   --from-backup PATH: parse a .dump.dl pg_dump file directly (not yet
//                       implemented -- prints a notice and exits)
//
// Synthesised fields are documented in event_enricher.cpp with TODO markers.

#include <libpq-fe.h>

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/strings/str_split.h"

#include "event_enricher.hpp"
#include "pg_util.hpp"
#include "util.hpp"

ABSL_FLAG(std::string, db_conn,
          "host=/run/postgresql port=5433 dbname=unifi-protect user=postgres",
          "libpq conninfo for the Protect database");
ABSL_FLAG(std::string, camera_id, "",
          "Protect cameraId (UUID-like string) to enrich");
ABSL_FLAG(std::string, date, "",
          "UTC day, format YYYY-MM-DD");
ABSL_FLAG(int, image_width, 2560,
          "Camera image width in pixels (used to size placeholder bboxes)");
ABSL_FLAG(int, image_height, 1440,
          "Camera image height in pixels");
ABSL_FLAG(std::string, from_backup, "",
          "Read events from a .dump.dl pg_dump file at PATH instead of the "
          "live database.  Not yet implemented.");
ABSL_FLAG(bool, dry_run, false,
          "If true, ROLLBACK after applying so nothing persists.  Useful for "
          "verifying the SQL is well-formed without touching the live DB.");

namespace {

// Parse "YYYY-MM-DD" -> Unix ms at 00:00 UTC.  Returns -1 on failure.
int64_t ParseDateToUtcMs(const std::string& s) {
  std::tm tm{};
  std::istringstream ss(s);
  ss >> std::get_time(&tm, "%Y-%m-%d");
  if (ss.fail()) return -1;
  // timegm is UTC -- portable manual computation since std::mktime is local.
  // tm_year is years since 1900; tm_mon is 0-based.
  // Use C standard library timegm via env hack-free approach:
  std::time_t t = timegm(&tm);
  if (t == static_cast<std::time_t>(-1)) return -1;
  return static_cast<int64_t>(t) * 1000;
}

// Escape a string for inclusion in a SQL literal (' -> '').
// libpq's PQescapeLiteral would be more correct but adds an alloc step;
// the strings we substitute here are UUIDs and short identifiers from
// data we just selected from the same DB, so simple escaping is fine.
std::string SqlLiteral(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  out += '\'';
  for (char c : s) {
    if (c == '\'') out += '\'';
    out += c;
  }
  out += '\'';
  return out;
}

// Read a SELECT into rows of strings.  Each row is a vector<string>; NULL
// values become an empty string AND null_flags[i] = true.
struct Row {
  std::vector<std::string> values;
  std::vector<bool>        is_null;
};

bool RunQuery(PGconn* conn, const std::string& sql, std::vector<Row>* out) {
  out->clear();
  PGresult* r = onvif::pg::ExecWithTimeout(conn, -1, sql.c_str());
  if (PQresultStatus(r) != PGRES_TUPLES_OK) {
    std::fprintf(stderr, "query failed: %s\nSQL: %s\n",
                 PQerrorMessage(conn), sql.c_str());
    PQclear(r);
    return false;
  }
  int nrows = PQntuples(r);
  int ncols = PQnfields(r);
  out->reserve(nrows);
  for (int i = 0; i < nrows; ++i) {
    Row row;
    row.values.reserve(ncols);
    row.is_null.reserve(ncols);
    for (int c = 0; c < ncols; ++c) {
      bool null = PQgetisnull(r, i, c);
      row.is_null.push_back(null);
      row.values.emplace_back(null ? "" : PQgetvalue(r, i, c));
    }
    out->push_back(std::move(row));
  }
  PQclear(r);
  return true;
}

bool RunStmt(PGconn* conn, const std::string& sql) {
  PGresult* r = onvif::pg::ExecWithTimeout(conn, -1, sql.c_str());
  ExecStatusType s = PQresultStatus(r);
  if (s != PGRES_COMMAND_OK && s != PGRES_TUPLES_OK) {
    std::fprintf(stderr, "exec failed: %s\nSQL: %s\n",
                 PQerrorMessage(conn), sql.c_str());
    PQclear(r);
    return false;
  }
  PQclear(r);
  return true;
}

// Parse json array of strings like ["vehicle"] -- minimal: pull tokens
// between the quotes.  Sufficient for events.smartDetectTypes which is
// always a simple string array.
std::vector<std::string> ParseStringJsonArray(const std::string& s) {
  std::vector<std::string> out;
  size_t i = 0;
  while (i < s.size()) {
    if (s[i] == '"') {
      size_t j = i + 1;
      while (j < s.size() && s[j] != '"') ++j;
      if (j > i + 1) out.push_back(s.substr(i + 1, j - i - 1));
      i = j + 1;
    } else {
      ++i;
    }
  }
  return out;
}

}  // namespace

int main(int argc, char** argv) {
  std::vector<char*> positional = absl::ParseCommandLine(argc, argv);
  absl::InitializeLog();

  if (!absl::GetFlag(FLAGS_from_backup).empty()) {
    std::fprintf(stderr,
                 "--from-backup is not yet implemented.  For now, "
                 "use tools/restore_events_from_backup.py to seed the live DB "
                 "from a pg_dump backup, then run this tool against the live "
                 "DB.\n");
    return 2;
  }

  const std::string cam = absl::GetFlag(FLAGS_camera_id);
  const std::string day = absl::GetFlag(FLAGS_date);
  if (cam.empty() || day.empty()) {
    std::fprintf(stderr, "usage: enrich_events --camera-id ID --date YYYY-MM-DD "
                         "[--image-width W] [--image-height H] [--dry-run]\n");
    return 1;
  }

  int64_t day_start = ParseDateToUtcMs(day);
  if (day_start < 0) {
    std::fprintf(stderr, "invalid --date '%s'\n", day.c_str());
    return 1;
  }
  int64_t day_end = day_start + 86'400'000;

  const int W = absl::GetFlag(FLAGS_image_width);
  const int H = absl::GetFlag(FLAGS_image_height);

  // ---- connect ----
  PGconn* conn = PQconnectdb(absl::GetFlag(FLAGS_db_conn).c_str());
  if (PQstatus(conn) != CONNECTION_OK) {
    std::fprintf(stderr, "connect failed: %s\n", PQerrorMessage(conn));
    PQfinish(conn);
    return 1;
  }

  // ---- pull events ----
  std::string sql_events =
      "SELECT id, type, start, \"end\", score, "
      "       COALESCE(\"smartDetectTypes\"::text, '[]'), "
      "       COALESCE(\"thumbnailId\", '') "
      "FROM events "
      "WHERE \"cameraId\" = " + SqlLiteral(cam) +
      " AND start >= " + std::to_string(day_start) +
      " AND start <  " + std::to_string(day_end) +
      " ORDER BY start";
  std::vector<Row> events_rows;
  if (!RunQuery(conn, sql_events, &events_rows)) { PQfinish(conn); return 1; }

  if (events_rows.empty()) {
    std::fprintf(stderr, "no events for cameraId=%s on %s\n",
                 cam.c_str(), day.c_str());
    PQfinish(conn); return 0;
  }

  // ---- pull per-object detectionLabels ----
  // Build a list of event ids for an IN(...) clause.
  std::string event_ids_csv;
  for (size_t i = 0; i < events_rows.size(); ++i) {
    if (i) event_ids_csv += ',';
    event_ids_csv += SqlLiteral(events_rows[i].values[0]);
  }
  std::string sql_objs =
      "SELECT \"eventId\", \"objectId\" "
      "FROM \"detectionLabels\" "
      "WHERE \"objectId\" IS NOT NULL "
      "  AND \"eventId\" IN (" + event_ids_csv + ")";
  std::vector<Row> obj_rows;
  if (!RunQuery(conn, sql_objs, &obj_rows)) { PQfinish(conn); return 1; }

  // Group object UUIDs by eventId.
  std::map<std::string, std::vector<std::string>> objects_by_event;
  for (const auto& r : obj_rows) {
    objects_by_event[r.values[0]].push_back(r.values[1]);
  }

  // ---- begin transaction ----
  if (!RunStmt(conn, "BEGIN")) { PQfinish(conn); return 1; }

  int events_updated  = 0;
  int objects_created = 0;
  for (const auto& er : events_rows) {
    onvif::enricher::EventInput ev;
    ev.event_id           = er.values[0];
    ev.event_type         = er.values[1];
    ev.start_ms           = std::stoull(er.values[2]);
    ev.end_ms             = er.is_null[3] ? ev.start_ms : std::stoull(er.values[3]);
    ev.score              = er.is_null[4] ? 0 : std::stoi(er.values[4]);
    ev.smart_detect_types = ParseStringJsonArray(er.values[5]);
    ev.thumbnail_id       = er.values[6];
    ev.camera_id          = cam;
    ev.image_width        = W;
    ev.image_height       = H;
    ev.object_ids         = objects_by_event[ev.event_id];

    const std::string det_type = ev.smart_detect_types.empty() ? std::string("unknown")
                                                                : ev.smart_detect_types.front();

    // UPDATE events.metadata + thumbnailFullfovId.
    std::string md = onvif::enricher::BuildEnrichedMetadata(ev);
    std::string sql_upd =
        "UPDATE events SET metadata = " + SqlLiteral(md) + "::json, "
        // TODO: thumbnailFullfovId should be a separate full-FOV crop; for now
        // we reuse the regular thumbnail so the UI has something to render.
        "\"thumbnailFullfovId\" = " + SqlLiteral(ev.thumbnail_id) +
        " WHERE id = " + SqlLiteral(ev.event_id);
    if (!RunStmt(conn, sql_upd)) { RunStmt(conn, "ROLLBACK"); PQfinish(conn); return 1; }
    ++events_updated;

    // INSERT smartDetectObjects + smartDetectObjectAreas per object.
    for (const auto& oid : ev.object_ids) {
      std::string attrs = onvif::enricher::BuildSmartDetectObjectAttributes(
          ev.score, det_type);

      std::string sql_sdo =
          "INSERT INTO \"smartDetectObjects\" "
          "(id, \"eventId\", \"cameraId\", \"thumbnailId\", type, attributes, "
          " \"detectedAt\", \"createdAt\", \"updatedAt\", metadata) "
          "VALUES (" +
            SqlLiteral(oid) + ", " +
            SqlLiteral(ev.event_id) + ", " +
            SqlLiteral(ev.camera_id) + ", " +
            SqlLiteral(ev.thumbnail_id) + ", " +
            SqlLiteral(det_type) + ", " +
            SqlLiteral(attrs) + "::json, " +
            std::to_string(ev.start_ms) + ", "
            "now(), now(), '{}'::json) "
          "ON CONFLICT (id) DO NOTHING";
      if (!RunStmt(conn, sql_sdo)) { RunStmt(conn, "ROLLBACK"); PQfinish(conn); return 1; }

      auto bb = onvif::enricher::PlaceholderBbox(W, H, det_type);
      // Deterministic UUIDv5-ish id derived from objectId so re-runs don't
      // double-insert.  We don't have OpenSSL linked into this tiny tool, so
      // we use a fake-deterministic id: SHA-free, derived by string prefix.
      // The actual PG schema only requires uniqueness of the row id.
      std::string area_id = "sda-" + oid;  // TODO: real UUIDv5
      std::string sql_sda =
          "INSERT INTO \"smartDetectObjectAreas\" "
          "(id, \"smartDetectObjectId\", \"areaIndexes\", "
          " \"boundingX1\", \"boundingY1\", \"boundingX2\", \"boundingY2\", "
          " \"detectedAt\", \"lastSeenAt\") "
          "VALUES (" +
            SqlLiteral(area_id) + ", " +
            SqlLiteral(oid) + ", " +
            // TODO: derive areaIndexes from bbox intersection with the 12x10
            // grid, not the full grid as we do here.
            onvif::enricher::FullGridAreaIndexesSqlArray() + ", " +
            std::to_string(bb.x1) + ", " + std::to_string(bb.y1) + ", " +
            std::to_string(bb.x2) + ", " + std::to_string(bb.y2) + ", " +
            std::to_string(ev.start_ms) + ", " + std::to_string(ev.end_ms) + ") "
          "ON CONFLICT (id) DO NOTHING";
      if (!RunStmt(conn, sql_sda)) { RunStmt(conn, "ROLLBACK"); PQfinish(conn); return 1; }
      ++objects_created;
    }
  }

  bool ok = RunStmt(conn,
                    absl::GetFlag(FLAGS_dry_run) ? "ROLLBACK" : "COMMIT");
  PQfinish(conn);

  std::printf("%s: %d events updated, %d smartDetectObjects+Areas rows "
              "attempted (ON CONFLICT DO NOTHING)\n",
              absl::GetFlag(FLAGS_dry_run) ? "dry-run (rolled back)" : "applied",
              events_updated, objects_created);
  return ok ? 0 : 1;
}
