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

#include "msr_backfill.hpp"

#include <libpq-fe.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/log/log.h"

namespace onvif {
namespace msr_backfill {

namespace {

std::string pg_err(PGresult* r) {
  const char* m = PQresultErrorMessage(r);
  return m ? std::string(m) : std::string("<nil>");
}

}  // namespace

Stats run(const std::string& db_conn, MsrClient* msr, int days, bool apply) {
  Stats s;
  if (days <= 0) return s;
  if (apply && msr == nullptr) {
    LOG(ERROR) << "[backfill] apply requested but MsrClient is null";
    return s;
  }

  PGconn* conn = PQconnectdb(db_conn.c_str());
  if (PQstatus(conn) != CONNECTION_OK) {
    LOG(ERROR) << "[backfill] pg connect failed: " << PQerrorMessage(conn);
    PQfinish(conn);
    return s;
  }

  // Select candidate events.  Bind `days` as a text param that we cast in
  // SQL to avoid libpq int-width portability concerns.
  const std::string days_str = std::to_string(days);
  const char* sel_params[1] = { days_str.c_str() };
  PGresult* res = PQexecParams(conn,
      "SELECT e.id, e.\"thumbnailId\", e.\"cameraId\", e.start, c.mac "
      "FROM events e JOIN cameras c ON e.\"cameraId\" = c.id "
      "WHERE c.\"isThirdPartyCamera\" = true "
      "  AND e.\"thumbnailId\" IS NOT NULL "
      "  AND LENGTH(e.\"thumbnailId\") = 24 "
      "  AND e.start > ("
      "      (EXTRACT(EPOCH FROM NOW()) * 1000)::bigint"
      "      - ($1::bigint * 86400000)) "
      "ORDER BY e.start DESC",
      1, nullptr, sel_params, nullptr, nullptr, 0);
  if (PQresultStatus(res) != PGRES_TUPLES_OK) {
    LOG(ERROR) << "[backfill] candidate query failed: " << pg_err(res);
    PQclear(res);
    PQfinish(conn);
    return s;
  }

  const int n = PQntuples(res);
  LOG(INFO) << "[backfill] " << n << " candidate event(s), apply="
            << (apply ? "true" : "false (dry run)");

  for (int i = 0; i < n; ++i) {
    ++s.examined;
    const std::string event_id = PQgetvalue(res, i, 0);
    const std::string old_tid  = PQgetvalue(res, i, 1);
    const std::string cam_id   = PQgetvalue(res, i, 2);
    const std::string mac      = PQgetvalue(res, i, 4);

    if (mac.empty()) {
      ++s.skipped_missing_mac;
      LOG(WARNING) << "[backfill] event=" << event_id
                   << " cam=" << cam_id << " has no MAC; skipping";
      continue;
    }

    // Fetch thumbnail bytes.
    const char* th_params[1] = { old_tid.c_str() };
    PGresult* tr = PQexecParams(conn,
        "SELECT content FROM thumbnails WHERE id = $1",
        1, nullptr, th_params, nullptr, nullptr, 1 /* want binary */);
    if (PQresultStatus(tr) != PGRES_TUPLES_OK) {
      LOG(ERROR) << "[backfill] thumb query failed for " << old_tid
                 << ": " << pg_err(tr);
      PQclear(tr);
      ++s.failed_update;
      continue;
    }
    if (PQntuples(tr) == 0 || PQgetisnull(tr, 0, 0)) {
      ++s.skipped_missing_thumb;
      PQclear(tr);
      continue;
    }
    const int jpeg_len = PQgetlength(tr, 0, 0);
    if (jpeg_len <= 0) {
      ++s.skipped_empty_thumb;
      PQclear(tr);
      continue;
    }
    // Copy bytes out before we clear the result.
    std::string jpeg(PQgetvalue(tr, 0, 0), static_cast<std::size_t>(jpeg_len));
    PQclear(tr);

    if (!apply) {
      // Dry run: count this row as migratable without calling MSR.
      ++s.migrated;
      if ((s.examined % 100) == 0)
        LOG(INFO) << "[backfill] scanned " << s.examined << "/" << n;
      continue;
    }

    // Apply: push to MSR, update events + smartDetectObjects, delete old row.
    const std::string new_tid = msr->StoreSnapshot(mac, jpeg.data(),
                                                   jpeg.size());
    if (new_tid.empty()) {
      ++s.failed_msr;
      LOG(WARNING) << "[backfill] MSR StoreSnapshots failed for event="
                   << event_id << " mac=" << mac;
      continue;
    }

    // Transactional DB update.
    PGresult* br = PQexec(conn, "BEGIN");
    PQclear(br);

    bool tx_ok = true;
    {
      const char* p[2] = { new_tid.c_str(), event_id.c_str() };
      PGresult* r = PQexecParams(conn,
          "UPDATE events SET \"thumbnailId\" = $1 WHERE id = $2",
          2, nullptr, p, nullptr, nullptr, 0);
      if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        LOG(ERROR) << "[backfill] events update failed: " << pg_err(r);
        tx_ok = false;
      }
      PQclear(r);
    }
    if (tx_ok) {
      const char* p[3] = { new_tid.c_str(), event_id.c_str(),
                           old_tid.c_str() };
      PGresult* r = PQexecParams(conn,
          "UPDATE \"smartDetectObjects\" SET \"thumbnailId\" = $1 "
          "WHERE \"eventId\" = $2 AND \"thumbnailId\" = $3",
          3, nullptr, p, nullptr, nullptr, 0);
      if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        LOG(ERROR) << "[backfill] smartDetectObjects update failed: "
                   << pg_err(r);
        tx_ok = false;
      }
      PQclear(r);
    }
    if (tx_ok) {
      const char* p[1] = { old_tid.c_str() };
      PGresult* r = PQexecParams(conn,
          "DELETE FROM thumbnails WHERE id = $1",
          1, nullptr, p, nullptr, nullptr, 0);
      if (PQresultStatus(r) != PGRES_COMMAND_OK) {
        LOG(ERROR) << "[backfill] thumbnails delete failed: " << pg_err(r);
        tx_ok = false;
      }
      PQclear(r);
    }

    if (tx_ok) {
      PGresult* cr = PQexec(conn, "COMMIT");
      if (PQresultStatus(cr) != PGRES_COMMAND_OK) {
        LOG(ERROR) << "[backfill] commit failed: " << pg_err(cr);
        tx_ok = false;
      }
      PQclear(cr);
    }
    if (!tx_ok) {
      PGresult* rr = PQexec(conn, "ROLLBACK");
      PQclear(rr);
      ++s.failed_update;
      continue;
    }

    ++s.migrated;
    if ((s.migrated % 100) == 0)
      LOG(INFO) << "[backfill] migrated " << s.migrated << "/" << n
                << " (last: " << event_id << " -> " << new_tid << ")";
  }

  PQclear(res);
  PQfinish(conn);

  LOG(INFO) << "[backfill] done: examined=" << s.examined
            << " migrated=" << s.migrated
            << " skipped_missing_thumb=" << s.skipped_missing_thumb
            << " skipped_missing_mac=" << s.skipped_missing_mac
            << " skipped_empty_thumb=" << s.skipped_empty_thumb
            << " failed_msr=" << s.failed_msr
            << " failed_update=" << s.failed_update;
  return s;
}

}  // namespace msr_backfill
}  // namespace onvif
