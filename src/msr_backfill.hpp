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

#ifndef SRC_MSR_BACKFILL_HPP_
#define SRC_MSR_BACKFILL_HPP_

#include <string>

#include "msr_client.hpp"

namespace onvif {
namespace msr_backfill {

struct Stats {
  int examined               = 0;
  int migrated               = 0;
  int skipped_missing_thumb  = 0;
  int skipped_missing_mac    = 0;
  int skipped_empty_thumb    = 0;
  int failed_msr             = 0;
  int failed_update          = 0;
};

// Migrates pre-MSR third-party thumbnail rows to native MSR-backed storage.
//
// Scans `events` joined to `cameras` for rows where
//   cameras.isThirdPartyCamera = true
//   events.thumbnailId IS NOT NULL AND LENGTH(events.thumbnailId) = 24
//   events.start > now - days*86_400_000
// then, for each row:
//   1. reads the legacy thumbnail bytes from `thumbnails.content`
//   2. when apply=true, POSTs them through
//      MsrClient::StoreSnapshot(mac, jpeg) to obtain a new MSR-format id
//      (<MAC>-<ts_ms>, length 26) and atomically updates events.thumbnailId
//      + smartDetectObjects.thumbnailId, then deletes the old
//      `thumbnails` row in a single transaction.
//   3. when apply=false (dry run), does NOT call MSR — MSR has no delete
//      API and a dry run should not pollute its storage.  Counts rows
//      whose thumbnail content exists and would be migrated.
//
// Logs progress every 100 rows.  Returns aggregate counters.
Stats run(const std::string& db_conn, MsrClient* msr, int days, bool apply);

}  // namespace msr_backfill
}  // namespace onvif

#endif  // SRC_MSR_BACKFILL_HPP_
