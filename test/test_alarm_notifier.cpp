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
 * test_alarm_notifier.cpp
 *
 * White-box tests for AlarmNotifier::parse_automations via a friend struct
 * declared in alarm_notifier.hpp.  Covers the JSON shapes we have actually
 * seen from the Protect API: enable/disable, condition sources, device
 * filters, cooldown, and "deleted" entries being dropped.
 */

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "alarm_notifier.hpp"

namespace onvif {

// Test seam declared as `friend` in AlarmNotifier so we can reach the private
// static parser without exposing it to the public API.
struct AlarmNotifierTest {
  static std::vector<AlarmNotifier::AutomationEntry> parse(
      const std::string& json) {
    return AlarmNotifier::parse_automations(json);
  }
};

}  // namespace onvif

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
  using onvif::AlarmNotifierTest;

  // Empty array parses to zero entries.
  {
    auto v = AlarmNotifierTest::parse("[]");
    check(v.empty(), "empty array -> 0 entries");
  }

  // Single enabled automation with one trigger and one source device.
  {
    const std::string json = R"([{
      "id": "a1",
      "name": "Porch person",
      "enable": true,
      "conditions": [{"source":"person"}],
      "sources":    [{"device":"FC5F49CA68D4"}],
      "cooldown":   {"enable": true, "timeout": 15000}
    }])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.size() == 1, "one automation parsed");
    if (v.size() == 1) {
      check(v[0].id == "a1", "id extracted");
      check(v[0].name == "Porch person", "name extracted");
      check(v[0].enabled, "enabled=true parsed");
      check(v[0].trigger_types.count("person") == 1, "trigger person present");
      check(v[0].trigger_types.size() == 1, "trigger_types size 1");
      check(v[0].source_devices.count("FC5F49CA68D4") == 1, "source MAC present");
      check(v[0].cooldown_enabled, "cooldown_enabled true");
      check(v[0].cooldown_ms == 15000, "cooldown_ms 15000");
    }
  }

  // Deleted entries are dropped.
  {
    const std::string json = R"([
      {"id":"keep","enable":true,"conditions":[{"source":"vehicle"}]},
      {"id":"drop","enable":true,"deleted":true,"conditions":[{"source":"person"}]}
    ])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.size() == 1, "deleted entry dropped");
    if (!v.empty()) {
      check(v[0].id == "keep", "surviving id == 'keep'");
    }
  }

  // Entries with no trigger_types are dropped (no-op alarm would never fire).
  {
    const std::string json =
        R"([{"id":"bad","enable":true,"conditions":[]}])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.empty(), "no-trigger entry dropped");
  }

  // Empty sources array means "all cameras".
  {
    const std::string json = R"([{
      "id":"all",
      "enable":true,
      "conditions":[{"source":"person"}],
      "sources":[]
    }])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.size() == 1, "empty sources parses");
    if (!v.empty()) {
      check(v[0].source_devices.empty(),
            "source_devices empty means all cameras");
    }
  }

  // Multiple trigger types collected into the set.
  {
    const std::string json = R"([{
      "id":"multi",
      "enable":true,
      "conditions":[
        {"source":"person"},
        {"source":"vehicle"},
        {"source":"animal"}
      ]
    }])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.size() == 1 && v[0].trigger_types.size() == 3,
          "three trigger types collected");
  }

  // Disabled automation is still returned (caller filters on enabled).
  {
    const std::string json = R"([{
      "id":"off",
      "enable":false,
      "conditions":[{"source":"person"}]
    }])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.size() == 1 && !v[0].enabled, "disabled retained, enable=false");
  }

  // Garbage input returns empty.
  {
    auto v = AlarmNotifierTest::parse("this is not json");
    check(v.empty(), "garbage -> empty");
  }

  // Escaped quotes inside strings don't fool the depth tracker.
  {
    const std::string json =
        R"([{"id":"esc","name":"hi \"there\"","enable":true,)"
        R"("conditions":[{"source":"person"}]}])";
    auto v = AlarmNotifierTest::parse(json);
    check(v.size() == 1, "escaped quotes in name don't confuse parser");
    if (!v.empty()) {
      check(v[0].id == "esc", "escaped-name id extracted");
    }
  }

  std::cerr << "PASS " << g_pass << " / FAIL " << g_fail << '\n';
  return g_fail == 0 ? 0 : 1;
}
