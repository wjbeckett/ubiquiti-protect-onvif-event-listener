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

#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "absl/synchronization/mutex.h"

namespace onvif {

/// Read the cached Protect API user ID from `cache_path`, or discover it from
/// the unifi-core PostgreSQL database and save it back to `cache_path`.
///
/// The cache file stores one user_id string per line.  When absent,
/// discover_protect_user_id() connects to `host=/run/postgresql port=5432
/// dbname=unifi-core user=postgres` and reads `SELECT user_id FROM
/// user_settings LIMIT 1`, then writes the result to `cache_path` for
/// subsequent runs.  The parent directory is created (mkdir 0755) if missing.
///
/// Returns the empty string on failure (no cache file, DB unreachable, or no
/// rows in user_settings).
std::string discover_protect_user_id(const std::string& cache_path);

/**
 * AlarmNotifier
 *
 * Triggers UniFi Protect automations (e.g. "Make Sound for detection") when a
 * smart detection event is recorded.  Uses the local Protect API on port 7080
 * with X-UserId auth bypass from localhost.
 *
 * Records automation history in the Protect DB so hits appear in the Protect UI
 * and respects the "ignore repeated" cooldown setting.
 *
 * Usage
 * -----
 *   AlarmNotifier notifier("http://localhost:7080", "user-uuid", db_connstr,
 *                          cache_path);
 *   notifier.refresh_alarms();
 *
 *   // On each detection event:
 *   notifier.notify("person", "FC5F49CA68D4", event_id, ts_ms);
 *
 * Thread-safe: notify() may be called concurrently from multiple camera threads.
 *
 * 401 self-heal: if a Protect API call returns 401 (typically because Protect
 * rotated the user_id during an upgrade), we re-query the unifi-core DB for a
 * fresh user_id, persist it to `user_id_cache_path` if non-empty, and retry
 * the request once.  Re-discovery is rate-limited to one attempt per minute
 * so persistent 401s don't hammer the DB.
 */
class AlarmNotifier {
 public:
  AlarmNotifier(std::string protect_url,
                std::string user_id,
                std::string db_connstr = "",
                std::string user_id_cache_path = "");

  /// Fetch the current automation list from Protect API and cache it.
  void refresh_alarms();

  /// Trigger matching Protect automations for a detection event.
  ///   obj_type   -- "person", "vehicle", "animal", or "package"
  ///   camera_mac -- uppercase no-colon MAC, e.g. "FC5F49CA68D4"
  ///   event_id   -- UUID of the inserted events row
  ///   ts_ms      -- event start timestamp (ms since Unix epoch)
  void notify(const std::string& obj_type,
              const std::string& camera_mac,
              const std::string& event_id,
              uint64_t ts_ms);

 private:
  struct AutomationEntry {
    std::string id;
    std::string name;
    std::set<std::string> trigger_types;   // "person", "vehicle", etc.
    std::set<std::string> source_devices;  // camera MACs (empty = all cameras)
    bool enabled = false;
    bool cooldown_enabled = false;
    uint64_t cooldown_ms = 0;
  };

  // Grant the white-box test access to the private static parser and the
  // AutomationEntry layout. Defined in test/test_alarm_notifier.cpp.
  friend struct AlarmNotifierTest;

  std::string protect_url_;
  std::string db_connstr_;
  std::string user_id_cache_path_;
  absl::Mutex mu_;
  // user_id_ is mutated by try_refresh_user_id() on observed 401s.
  std::string user_id_;  // protected by mu_
  std::chrono::steady_clock::time_point last_user_id_refresh_attempt_{};
  // ^^ protected by mu_
  std::vector<AutomationEntry> automations_;  // protected by mu_
  std::map<std::string, uint64_t> last_fired_;  // automation_id → ms, protected by mu_
  std::chrono::steady_clock::time_point last_refresh_{};

  // Minimum interval between user_id re-discovery attempts.  Prevents
  // hammering the unifi-core DB on persistent 401s.
  static constexpr std::chrono::seconds kUserIdRefreshInterval{60};

  static std::vector<AutomationEntry> parse_automations(
      const std::string& json);
  static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* userdata);

  // Pure rate-limit predicate.  Returns true iff `now` is at least
  // kUserIdRefreshInterval past `last_attempt` (or last_attempt is the
  // default-constructed zero time).  Visible for testing via friend.
  static bool should_attempt_user_id_refresh(
      std::chrono::steady_clock::time_point now,
      std::chrono::steady_clock::time_point last_attempt);

  // Returns the current user_id under mu_.
  std::string current_user_id() const;
  // Re-discover user_id from unifi-core (via query_user_id_from_unifi_core).
  // Rate-limited.  Returns true iff user_id_ was updated.
  bool try_refresh_user_id();

  std::string http_get(const std::string& url);
  void http_post(const std::string& url, const std::string& body);
  // Inner request workers; return the HTTP status code.  perform_get
  // also writes the response body into `*body`.  Empty body and non-200
  // codes are surfaced to the caller, which decides whether to retry
  // after a user_id refresh.
  long perform_get(const std::string& url, const std::string& user_id,  // NOLINT(runtime/int)
                   std::string* body);
  long perform_post(const std::string& url, const std::string& user_id,  // NOLINT(runtime/int)
                    const std::string& body);
  void record_history(const AutomationEntry& automation,
                      const std::string& obj_type,
                      const std::string& camera_mac,
                      const std::string& event_id,
                      uint64_t ts_ms);
};

}  // namespace onvif
