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

#pragma once

// Auto-recover events from Protect's own daily DB backups when we detect the
// events table has been wiped (typical cause: a firmware upgrade that resets
// the Protect cluster without warning us).  The recordingFiles + thumbnails
// UBV files survive the wipe and still hold the user's history; recovering
// the events row + rich-format sibling rows means the UI re-surfaces those
// recordings with the right markers.
//
// Gated by protect_version::IsAtLeast(7,1,0) -- on older Protect we don't
// touch the schema.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/status/status.h"

struct pg_conn;
typedef struct pg_conn PGconn;  // forward decl to avoid pulling in libpq-fe.h

namespace onvif {
namespace event_recovery {

// Options controlling the batched + throttled EnrichRestored loop.  A
// fire-and-forget call with defaults produces the same eventual effect
// as the previous single-transaction implementation -- every event that
// needs enrichment gets processed -- but with much better DB citizenship
// and clean cancellation.  Field-observed on issue #34: the old code
// dispatched a single monolithic SELECT that could exceed the per-
// connection statement_timeout on busy Protect clusters and silently
// abort the entire recovery pass; the batched loop sizes each SELECT
// small enough to stay well inside that limit.
struct EnrichOptions {
  int image_width  = 2560;
  int image_height = 1440;

  // Target wall-clock budget per batch (measured across the SELECT plus
  // all per-event UPDATE/INSERT calls in that batch).  The loop grows
  // and shrinks the SELECT LIMIT to home in on this figure; batches that
  // overshoot cause the next batch to shrink proportionally, batches
  // that finish in <target/2 double the next batch's size.
  std::chrono::milliseconds target_batch_ms{2000};

  // Duty-cycle throttle.  After a batch that took X ms of work, sleep
  // for `sleep_ratio * X` ms before the next batch.  1.0 = 50% duty
  // cycle (equal time working / sleeping); 0 disables the sleep.
  double sleep_ratio = 1.0;

  // Optional cancellation flag.  When non-null and the pointed-to
  // atomic reads true, the loop exits cleanly at the next batch
  // boundary or during an interruptible inter-batch sleep slice.
  std::atomic<bool>* cancelled = nullptr;
};

// Pure helper visible for testing.  Given a completed batch that
// processed `current_size` rows in `elapsed_ms`, decide the next
// batch's row count.  Grows on under-run, shrinks on over-run, clamps
// to [min_size, max_size].  Returns @p current_size unchanged when
// elapsed_ms is between target_ms/2 and target_ms (goldilocks zone).
int next_batch_size(int current_size,
                    int64_t elapsed_ms,
                    int64_t target_ms,
                    int min_size,
                    int max_size);

// One discovered backup file with its on-disk timestamp.
struct Backup {
  std::string path;        // absolute
  uint64_t    mtime_ms{0}; // file modification time (ms since epoch)
};

// Decide whether to trigger a recovery on this startup.  Logic:
//   - If protect_version::IsAtLeast(7,1,0) is false -> false (legacy Protect)
//   - Query oldest events.start and oldest recordingFiles.start.
//   - If oldest event is more than `threshold_ms` newer than oldest recording,
//     there is a gap that recordingFiles say should be populated -> true.
//   - If events table is empty -> true.
// Default threshold is 24h (giving slack for backup latency / time drift).
bool ShouldRecover(PGconn* conn, uint64_t threshold_ms = 86'400'000ULL);

// Test-friendly variant: pass the timestamps explicitly.  Production code
// uses the PGconn overload above.
bool ShouldRecoverFromTimestamps(int64_t oldest_event_ms,
                                  int64_t oldest_recording_ms,
                                  uint64_t threshold_ms = 86'400'000ULL);

// Scan @p dir for files matching `db_backup_partial.*.dump*` and return the
// most recent (highest mtime).  Returns empty optional if the directory does
// not exist or has no matching files.
std::optional<Backup> FindLatestBackup(const std::string& dir);

// Test-friendly variant: pick the newest entry from an explicit list.
std::optional<Backup> PickNewest(const std::vector<Backup>& candidates);

// Shell out to pg_restore (looking under common install paths for a 16+ binary
// that can read the dump.dl format).  Restores only the events, detectionLabels,
// and labels tables -- the only ones in the partial backup -- using
// `--data-only` and ON-CONFLICT-DO-NOTHING semantics.  Returns OK on success
// or a descriptive error.
absl::Status RestoreFromBackup(PGconn* conn, const std::string& dump_path);

// For every event whose metadata is missing the rich 7.1+ shape (no
// detectedAreas key), run event_enricher to populate metadata, set
// thumbnailFullfovId, and insert a paired smartDetectObjectAreas row per
// existing smartDetectObject.  Idempotent: re-running rewrites metadata to
// the same canonical synth.
//
// Runs as a batched, adaptive-size loop with a duty-cycle sleep between
// batches (see EnrichOptions).  Safe to run concurrently with normal
// Protect DB writes -- each batch commits row-by-row and the loop's
// SELECT filter naturally excludes rows already enriched.
absl::Status EnrichRestored(PGconn* conn, EnrichOptions opts);

// Convenience overload preserving the pre-batched signature.  All other
// options take their defaults from EnrichOptions -- notably a 2 s
// target per batch and a 50% duty cycle (sleep = work).
absl::Status EnrichRestored(PGconn* conn,
                             int image_width = 2560,
                             int image_height = 1440);

// High-level orchestrator: ShouldRecover() -> FindLatestBackup() ->
// RestoreFromBackup() -> EnrichRestored().  Logs each step.  Safe to call
// unconditionally -- it gates on protect_version internally.
absl::Status Run(PGconn* conn,
                  const std::string& backups_dir = "/srv/unifi-protect/dbBackups");

}  // namespace event_recovery
}  // namespace onvif
