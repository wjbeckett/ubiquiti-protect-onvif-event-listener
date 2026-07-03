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

#include <cstdio>
#include <cstdlib>
#include <vector>

#include "event_recovery.hpp"
#include "protect_version.hpp"

namespace {

#define CHECK(expr) do { \
  if (!(expr)) { \
    std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", \
                 __FILE__, __LINE__, #expr); \
    std::exit(1); \
  } \
} while (0)

// ShouldRecoverFromTimestamps -- pure decision-table tests.

void test_no_events_means_recover() {
  // events table empty (min(start) IS NULL -> -1).
  CHECK(onvif::event_recovery::ShouldRecoverFromTimestamps(
            /*event=*/-1, /*recording=*/1700000000000, 86400000));
}

void test_no_recordings_means_no_recover() {
  // No recordings to anchor against -- don't recover blindly.
  CHECK(!onvif::event_recovery::ShouldRecoverFromTimestamps(
            /*event=*/1700000000000, /*recording=*/-1, 86400000));
}

void test_event_older_than_recording_no_recover() {
  // Events go back further than recordings -- no wipe.
  CHECK(!onvif::event_recovery::ShouldRecoverFromTimestamps(
            /*event=*/1700000000000,
            /*recording=*/1701000000000,
            86400000));
}

void test_event_slightly_newer_within_threshold_no_recover() {
  // Event 12h newer than recording -- under 24h threshold -- no recover.
  const int64_t day = 86400000;
  CHECK(!onvif::event_recovery::ShouldRecoverFromTimestamps(
            /*event=*/1700000000000 + day/2,
            /*recording=*/1700000000000,
            /*threshold_ms=*/day));
}

void test_event_significantly_newer_recover() {
  // Event 7 days newer than recording -- well above 24h threshold.
  const int64_t day = 86400000;
  CHECK(onvif::event_recovery::ShouldRecoverFromTimestamps(
            /*event=*/1700000000000 + 7 * day,
            /*recording=*/1700000000000,
            /*threshold_ms=*/day));
}

void test_threshold_boundary_inclusive() {
  // Exactly at threshold: NOT recover (must be strictly greater).
  const int64_t day = 86400000;
  CHECK(!onvif::event_recovery::ShouldRecoverFromTimestamps(
            /*event=*/1700000000000 + day,
            /*recording=*/1700000000000,
            /*threshold_ms=*/day));
}

// PickNewest -- file-discovery helper tests.

void test_pick_newest_empty() {
  CHECK(!onvif::event_recovery::PickNewest({}).has_value());
}

void test_pick_newest_single() {
  auto r = onvif::event_recovery::PickNewest({{"/foo/a.dump", 100}});
  CHECK(r.has_value());
  CHECK(r->path == "/foo/a.dump");
  CHECK(r->mtime_ms == 100);
}

void test_pick_newest_multiple() {
  std::vector<onvif::event_recovery::Backup> v = {
    {"/foo/old.dump", 100},
    {"/foo/newer.dump", 200},
    {"/foo/newest.dump", 300},
    {"/foo/middling.dump", 150},
  };
  auto r = onvif::event_recovery::PickNewest(v);
  CHECK(r.has_value());
  CHECK(r->path == "/foo/newest.dump");
  CHECK(r->mtime_ms == 300);
}

void test_pick_newest_stable_on_ties() {
  // Ties -> first encountered wins (our impl picks <= base, so >= keeps base).
  std::vector<onvif::event_recovery::Backup> v = {
    {"/foo/a.dump", 100},
    {"/foo/b.dump", 100},
  };
  auto r = onvif::event_recovery::PickNewest(v);
  CHECK(r.has_value());
  CHECK(r->path == "/foo/a.dump");
}

// --- next_batch_size: adaptive sizing decision table. ---

void test_batch_stays_put_in_goldilocks_zone() {
  // batch that took between target/2 and target -> unchanged size.
  CHECK(onvif::event_recovery::next_batch_size(
            /*current=*/25, /*elapsed=*/1500,
            /*target=*/2000, /*min=*/5, /*max=*/500) == 25);
  CHECK(onvif::event_recovery::next_batch_size(
            25, 1000, 2000, 5, 500) == 25);
}

void test_batch_grows_when_underrunning() {
  // Under target/2 -> double.
  CHECK(onvif::event_recovery::next_batch_size(
            25, 400, 2000, 5, 500) == 50);
  CHECK(onvif::event_recovery::next_batch_size(
            50, 100, 2000, 5, 500) == 100);
}

void test_batch_shrinks_when_overrunning() {
  // 25 rows took 4000 ms, target 2000 -> shrink proportionally.
  // 25 * 2000/4000 = 12.5 -> floor to 12.
  CHECK(onvif::event_recovery::next_batch_size(
            25, 4000, 2000, 5, 500) == 12);
  // Extreme overrun: 100 rows took 20 s, target 2 s -> 10 rows.
  CHECK(onvif::event_recovery::next_batch_size(
            100, 20000, 2000, 5, 500) == 10);
}

void test_batch_clamps_to_min_max() {
  // Shrink would go below min -> clamps at min.
  CHECK(onvif::event_recovery::next_batch_size(
            5, 60000, 2000, /*min=*/5, /*max=*/500) == 5);
  // Grow would go above max -> clamps at max.
  CHECK(onvif::event_recovery::next_batch_size(
            300, 100, 2000, 5, /*max=*/500) == 500);
  // Current already above max normalises down.
  CHECK(onvif::event_recovery::next_batch_size(
            9999, 1500, 2000, 5, 500) == 500);
}

void test_batch_no_change_on_zero_elapsed() {
  // Guard against divide-by-zero / degenerate input.
  CHECK(onvif::event_recovery::next_batch_size(
            25, 0, 2000, 5, 500) == 25);
}

}  // namespace

int main() {
  test_no_events_means_recover();
  test_no_recordings_means_no_recover();
  test_event_older_than_recording_no_recover();
  test_event_slightly_newer_within_threshold_no_recover();
  test_event_significantly_newer_recover();
  test_threshold_boundary_inclusive();
  test_pick_newest_empty();
  test_pick_newest_single();
  test_pick_newest_multiple();
  test_pick_newest_stable_on_ties();
  test_batch_stays_put_in_goldilocks_zone();
  test_batch_grows_when_underrunning();
  test_batch_shrinks_when_overrunning();
  test_batch_clamps_to_min_max();
  test_batch_no_change_on_zero_elapsed();
  std::printf("event_recovery tests passed\n");
  return 0;
}
