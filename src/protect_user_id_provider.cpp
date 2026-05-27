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

#include "protect_user_id_provider.hpp"

#include <sys/stat.h>

#include <libpq-fe.h>

#include <fstream>
#include <string>
#include <utility>

#include "absl/log/log.h"
#include "pg_util.hpp"

namespace onvif {

namespace {

// Query unifi-core's user_settings table for the owner's user_id.  No
// cache.  Returns "" on any failure.
std::string query_user_id_from_unifi_core() {
  PGconn* conn = PQconnectdb(
      "host=/run/postgresql port=5432 dbname=unifi-core user=postgres");
  if (PQstatus(conn) != CONNECTION_OK) {
    LOG(ERROR) << "[user_id] cannot query unifi-core DB: "
               << PQerrorMessage(conn);
    PQfinish(conn);
    return {};
  }
  PGresult* res = onvif::pg::ExecWithTimeout(conn, -1,
      "SELECT user_id FROM user_settings LIMIT 1");
  std::string user_id;
  if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0) {
    user_id = PQgetvalue(res, 0, 0);
    while (!user_id.empty() && user_id.back() == ' ') user_id.pop_back();
  }
  PQclear(res);
  PQfinish(conn);
  return user_id;
}

}  // namespace

std::string discover_protect_user_id(const std::string& cache_path) {
  // 1. Try reading cached value.
  {
    std::ifstream f(cache_path);
    std::string line;
    if (f.is_open() && std::getline(f, line) && line.size() >= 32) {
      while (!line.empty() && (line.back() == '\n' || line.back() == '\r' ||
                               line.back() == ' '))
        line.pop_back();
      if (!line.empty()) {
        LOG(INFO) << "[user_id] loaded from " << cache_path;
        return line;
      }
    }
  }

  // 2. Query unifi-core.
  std::string user_id = query_user_id_from_unifi_core();
  if (user_id.empty()) {
    LOG(ERROR) << "[user_id] no user_id found in unifi-core user_settings";
    return {};
  }

  // 3. Cache to disk.
  {
    const size_t slash = cache_path.find_last_of('/');
    if (slash != std::string::npos && slash > 0) {
      (void)mkdir(cache_path.substr(0, slash).c_str(), 0755);
    }
    std::ofstream f(cache_path);
    if (f.is_open()) {
      f << user_id << '\n';
      LOG(INFO) << "[user_id] saved to " << cache_path;
    } else {
      LOG(ERROR) << "[user_id] could not write " << cache_path;
    }
  }
  return user_id;
}

ProtectUserIdProvider::ProtectUserIdProvider(std::string user_id,
                                              std::string cache_path)
    : cache_path_(std::move(cache_path)),
      user_id_(std::move(user_id)) {}  // NOLINT(whitespace/indent_namespace)

std::string ProtectUserIdProvider::current() const {
  absl::MutexLock lk(&mu_);
  return user_id_;
}

bool ProtectUserIdProvider::empty() const {
  absl::MutexLock lk(&mu_);
  return user_id_.empty();
}

bool ProtectUserIdProvider::should_attempt_refresh(
    std::chrono::steady_clock::time_point now,
    std::chrono::steady_clock::time_point last_attempt) {
  // Default-constructed time_point compares less than any real time
  // we'll record, so the first attempt is always allowed.
  if (last_attempt == std::chrono::steady_clock::time_point{}) return true;
  return now - last_attempt >= kRefreshInterval;
}

bool ProtectUserIdProvider::try_refresh() {
  using clock = std::chrono::steady_clock;
  {
    absl::MutexLock lk(&mu_);
    auto now = clock::now();
    if (!should_attempt_refresh(now, last_refresh_attempt_)) return false;
    last_refresh_attempt_ = now;
  }
  // DB query outside the lock to avoid holding mu_ across syscalls.
  std::string fresh = query_user_id_from_unifi_core();
  if (fresh.empty()) {
    LOG(WARNING) << "[user_id] refresh found no row in user_settings; "
                 << "keeping existing value";
    return false;
  }
  bool changed;
  {
    absl::MutexLock lk(&mu_);
    changed = (fresh != user_id_);
    if (changed) user_id_ = fresh;
  }
  if (!changed) {
    LOG(INFO) << "[user_id] refresh found same value -- "
              << "401 may not be auth-related";
    return false;
  }
  LOG(WARNING) << "[user_id] rotated; refreshed cache";
  if (!cache_path_.empty()) {
    std::ofstream f(cache_path_);
    if (f.is_open()) {
      f << fresh << '\n';
    } else {
      LOG(WARNING) << "[user_id] failed to write " << cache_path_;
    }
  }
  return true;
}

}  // namespace onvif
