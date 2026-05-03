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

/**
 * test_protect_user_id_provider.cpp
 *
 * Covers the public surface that doesn't require unifi-core:
 *   - current() returns what was passed in
 *   - empty() reflects current state
 *   - should_attempt_refresh() rate-limit predicate behaviour
 *
 * The DB query path (try_refresh's actual side-effect) requires
 * unifi-core PostgreSQL on /run/postgresql, which we don't have in
 * the sandbox.  That path is small and inspectable; the rate-limit
 * gating is what matters for correctness.
 */

#include <chrono>
#include <iostream>
#include <string>

#include "protect_user_id_provider.hpp"

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const char* label) {
  if (cond) {
    ++g_pass;
  } else {
    ++g_fail;
    std::cerr << "FAIL: " << label << '\n';
  }
}

int main() {
  using onvif::ProtectUserIdProvider;
  using clock = std::chrono::steady_clock;

  // current() / empty()
  {
    ProtectUserIdProvider p("abc-123", "/tmp/nonexistent-cache-path");
    check(p.current() == "abc-123", "current() returns ctor value");
    check(!p.empty(), "non-empty user_id -> empty()=false");
  }
  {
    ProtectUserIdProvider p("", "/tmp/nonexistent-cache-path");
    check(p.current().empty(), "empty user_id -> current()==\"\"");
    check(p.empty(), "empty user_id -> empty()=true");
  }

  // Rate-limit predicate.
  const auto interval = ProtectUserIdProvider::kRefreshInterval;

  // First attempt (last_attempt is the default-constructed zero time)
  // must always be allowed -- otherwise we'd never recover from a
  // rotation that happens before the first observed 401.
  {
    clock::time_point now = clock::now();
    clock::time_point never;
    check(ProtectUserIdProvider::should_attempt_refresh(now, never),
          "rate-limit: zero last_attempt always allows");
  }

  // Two attempts within the interval: second is denied.
  {
    clock::time_point t0 = clock::now();
    clock::time_point t1 = t0 + interval / 2;
    check(!ProtectUserIdProvider::should_attempt_refresh(t1, t0),
          "rate-limit: second attempt within interval denied");
  }

  // At the interval boundary: allowed.
  {
    clock::time_point t0 = clock::now();
    clock::time_point t1 = t0 + interval;
    check(ProtectUserIdProvider::should_attempt_refresh(t1, t0),
          "rate-limit: attempt at boundary allowed");
  }

  // Well past the interval: allowed.
  {
    clock::time_point t0 = clock::now();
    clock::time_point t1 = t0 + interval * 5;
    check(ProtectUserIdProvider::should_attempt_refresh(t1, t0),
          "rate-limit: attempt past interval allowed");
  }

  std::cerr << "PASS " << g_pass << " / FAIL " << g_fail << '\n';
  return g_fail == 0 ? 0 : 1;
}
