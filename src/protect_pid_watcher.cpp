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

#include "protect_pid_watcher.hpp"

#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <string>
#include <utility>

#include "absl/log/log.h"

namespace onvif {

ProtectPidWatcher::ProtectPidWatcher()
    : ProtectPidWatcher(std::chrono::seconds(10), std::chrono::seconds(300)) {}

ProtectPidWatcher::ProtectPidWatcher(
    std::chrono::seconds poll_interval,
    std::chrono::seconds settle_duration)
    : poll_interval_(poll_interval),
      settle_duration_(settle_duration),
      pid_provider_(&ProtectPidWatcher::read_systemd_main_pid),
      restart_action_(&ProtectPidWatcher::self_sigterm) {}  // NOLINT(whitespace/indent_namespace)

ProtectPidWatcher::~ProtectPidWatcher() { stop(); }

bool ProtectPidWatcher::start() {
  if (running_.exchange(true)) return false;
  thread_ = std::thread([this] { run(); });
  return true;
}

void ProtectPidWatcher::stop() {
  if (!running_.exchange(false)) return;
  if (thread_.joinable()) thread_.join();
}

void ProtectPidWatcher::set_pid_provider_for_testing(PidProvider p) {
  pid_provider_ = std::move(p);
}

void ProtectPidWatcher::set_restart_action_for_testing(RestartAction a) {
  restart_action_ = std::move(a);
}

void ProtectPidWatcher::run() {
  initial_pid_ = pid_provider_();
  observed_pid_.store(initial_pid_);
  LOG(INFO) << "[protect_watcher] initial unifi-protect MainPID="
            << initial_pid_ << " (poll=" << poll_interval_.count()
            << "s settle=" << settle_duration_.count() << "s)";

  while (running_) {
    // Sleep in 1 s chunks so stop() can wake us promptly.
    const int total_secs = static_cast<int>(poll_interval_.count());
    for (int i = 0; i < total_secs && running_; ++i)
      std::this_thread::sleep_for(std::chrono::seconds(1));
    if (!running_) break;

    if (tick_for_testing(std::chrono::steady_clock::now())) {
      // tick_for_testing already invoked restart_action_; we'll exit on
      // the next iteration since systemd is taking us down.
    }
  }
}

bool ProtectPidWatcher::tick_for_testing(
    std::chrono::steady_clock::time_point now) {
  if (restart_triggered_) return false;

  const pid_t pid = pid_provider_();
  observed_pid_.store(pid);

  // Protect not running -- wait for it to come back.  Don't treat
  // "missing" as a PID change because that would queue a restart for
  // whichever PID comes next, even if Protect's own restart bracket is
  // still in flight.
  if (pid <= 0) {
    return false;
  }

  // First positive PID observed.  If it differs from initial_pid_,
  // count it as the start of a pending settle window.
  if (initial_pid_ <= 0) {
    initial_pid_ = pid;
    LOG(INFO) << "[protect_watcher] late-bound initial MainPID=" << pid;
    return false;
  }

  if (pid == initial_pid_) {
    // No restart yet; clear any pending state and continue.
    if (pending_pid_ > 0) {
      LOG(INFO) << "[protect_watcher] pending PID " << pending_pid_
                << " went away; reverting to initial PID " << initial_pid_;
      pending_pid_ = -1;
    }
    return false;
  }

  // PID differs from initial.
  if (pid != pending_pid_) {
    // Either first time we've seen a new PID, or it changed again
    // (Protect restarting during its own restart window).  Restart
    // the settle timer.
    LOG(INFO) << "[protect_watcher] unifi-protect MainPID changed from "
              << initial_pid_ << " to " << pid
              << "; waiting " << settle_duration_.count()
              << "s for it to stabilise before restarting ourselves";
    pending_pid_ = pid;
    pending_pid_first_seen_ = now;
    return false;
  }

  // pid == pending_pid_ && pid != initial_pid_.  Check elapsed.
  const auto age =
      std::chrono::duration_cast<std::chrono::seconds>(now - pending_pid_first_seen_);
  if (age < settle_duration_) {
    // Still settling.  No log spam on every poll.
    return false;
  }

  LOG(INFO) << "[protect_watcher] unifi-protect MainPID=" << pid
            << " stable for " << age.count() << "s after restart"
            << "; requesting our own restart via SIGTERM";
  restart_triggered_ = true;
  restart_count_.fetch_add(1);
  restart_action_();
  return true;
}

// Resolves unifi-protect's MainPID via systemd.  Subprocess cost is
// negligible at a 10 s cadence.  Returns -1 on any read / parse error.
pid_t ProtectPidWatcher::read_systemd_main_pid() {
  FILE* fp = popen(
      "systemctl show unifi-protect --property=MainPID --value 2>/dev/null",
      "r");
  if (!fp) return -1;
  char buf[64] = {0};
  size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
  pclose(fp);
  if (n == 0) return -1;
  // Trim trailing whitespace.
  while (n > 0 &&
         (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' '))
    buf[--n] = '\0';
  if (buf[0] == '\0') return -1;
  char* end = nullptr;
  // libc requires `long` for strtol  // NOLINT(runtime/int)
  long pid = std::strtol(buf, &end, 10);  // NOLINT(runtime/int)
  if (end == buf || pid <= 0) return -1;
  return static_cast<pid_t>(pid);
}

void ProtectPidWatcher::self_sigterm() {
  // SIGTERM (not SIGKILL) so absl logs flush and systemd treats this as a
  // clean shutdown and just restarts us per the unit's Restart= policy.
  ::kill(getpid(), SIGTERM);
}

}  // namespace onvif
