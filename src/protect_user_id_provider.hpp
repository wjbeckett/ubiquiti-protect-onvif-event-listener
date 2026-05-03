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

#ifndef SRC_PROTECT_USER_ID_PROVIDER_HPP_
#define SRC_PROTECT_USER_ID_PROVIDER_HPP_

#include <chrono>
#include <string>

#include "absl/synchronization/mutex.h"

namespace onvif {

// One-shot discovery of the X-UserId value the local Protect API
// accepts for auth-bypass-from-localhost.  Reads `cache_path`; if
// missing, queries unifi-core's user_settings table and writes the
// result back.  Returns the empty string on total failure (no cache,
// DB unreachable, no rows in user_settings).
std::string discover_protect_user_id(const std::string& cache_path);

// Owns the live user_id used by every component that talks to the
// local Protect API (AlarmNotifier, motion_poller's MSR thumbnail
// fetcher, admin_server's thumbnail proxy).
//
// On observed 401 from Protect API, callers invoke try_refresh() to
// re-query unifi-core for a fresh user_id (typical cause: Protect
// rotated the user_id during an upgrade) and retry the request once
// with the new value.  Re-discovery is rate-limited to one attempt
// per kRefreshInterval to prevent persistent 401s from hammering the
// DB.
//
// Thread-safe: all public methods may be called from any thread.
class ProtectUserIdProvider {
 public:
  ProtectUserIdProvider(std::string user_id, std::string cache_path);

  // Current user_id.  Empty if discovery failed at startup.
  std::string current() const;

  // Whether a user_id is configured at all.  Equivalent to
  // !current().empty(), but doesn't allocate.
  bool empty() const;

  // Re-query unifi-core for a fresh user_id.  Rate-limited.
  // Returns true iff the cached value was updated.
  bool try_refresh();

  // Test seam: the rate-limit predicate, exposed for unit tests.
  static bool should_attempt_refresh(
      std::chrono::steady_clock::time_point now,
      std::chrono::steady_clock::time_point last_attempt);

  static constexpr std::chrono::seconds kRefreshInterval{60};

 private:
  std::string cache_path_;
  mutable absl::Mutex mu_;
  std::string user_id_;  // protected by mu_
  std::chrono::steady_clock::time_point last_refresh_attempt_{};
  // ^^ protected by mu_
};

}  // namespace onvif

#endif  // SRC_PROTECT_USER_ID_PROVIDER_HPP_
