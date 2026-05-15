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

#ifndef SRC_PROTECT_PID_WATCHER_HPP_
#define SRC_PROTECT_PID_WATCHER_HPP_

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <thread>

namespace onvif {

/**
 * ProtectPidWatcher — re-launch the recorder after unifi-protect restarts.
 *
 * Why: on every Protect restart (firmware upgrade, manual restart, crash) the
 * Protect controller re-syncs every camera row from the device's reported
 * capabilities a couple of minutes after start-up, which clobbers the
 * featureFlags writes our enable_smart_detect made for cameras whose
 * firmware does not natively advertise smart-detect (e.g. G3 Dome).  An
 * onvif-recorder start-up re-flip alone loses the race: we win at T+0 and
 * Protect overwrites us at ~T+3 min.
 *
 * This watcher polls Protect's MainPID; when it observes a change followed
 * by a stable @p settle_duration window (default 300 s), it asks systemd to
 * restart us by sending SIGTERM to our own PID.  systemd brings us back up;
 * the fresh start-up re-runs enable_smart_detect *after* Protect has
 * finished its sync, and the flip sticks.
 *
 * The settle window also guards against crash-looping when Protect itself
 * is crash-looping -- we only restart once Protect's new PID has stayed
 * alive long enough that the flip will actually survive.
 */
class ProtectPidWatcher {
 public:
  // Default: poll every 10 s, restart after Protect's new PID has been
  // stable for 300 s.
  ProtectPidWatcher();

  ProtectPidWatcher(std::chrono::seconds poll_interval,
                    std::chrono::seconds settle_duration);

  ~ProtectPidWatcher();

  ProtectPidWatcher(const ProtectPidWatcher&) = delete;
  ProtectPidWatcher& operator=(const ProtectPidWatcher&) = delete;

  // Begin watching.  Returns false if a thread is already running.
  bool start();

  // Stop the watcher and join its thread.  Idempotent.
  void stop();

  // ---- Test hooks ------------------------------------------------------

  // Override the function that reads Protect's MainPID.  Default uses
  // `systemctl show unifi-protect --property=MainPID --value`.
  // A return value <= 0 means "Protect not running" and is treated as a
  // PID change only if we previously observed a positive PID.
  using PidProvider = std::function<pid_t()>;
  void set_pid_provider_for_testing(PidProvider p);

  // Override the function that performs the "ask systemd to restart us"
  // action.  Default sends SIGTERM to getpid().  Tests can substitute a
  // counter increment.
  using RestartAction = std::function<void()>;
  void set_restart_action_for_testing(RestartAction a);

  // Observe state for tests.
  pid_t observed_pid_for_testing() const { return observed_pid_.load(); }
  uint64_t restart_count_for_testing() const { return restart_count_.load(); }

  // Run one poll iteration synchronously (no sleep, no thread).  Returns
  // true iff the iteration triggered the restart action.  Tests drive the
  // watcher this way instead of waiting for the timer.
  bool tick_for_testing(std::chrono::steady_clock::time_point now);

 private:
  void run();

  // Returns Protect's MainPID, or -1 if it cannot be determined.
  static pid_t read_systemd_main_pid();

  // Sends SIGTERM to our own PID so systemd restarts the service.
  static void self_sigterm();

  std::chrono::seconds poll_interval_;
  std::chrono::seconds settle_duration_;
  PidProvider     pid_provider_;
  RestartAction   restart_action_;

  std::thread thread_;
  std::atomic<bool> running_{false};

  // Per-iteration state (only touched by run() / tick_for_testing()).
  pid_t initial_pid_{-1};   // PID at our start-up (no restart on this one).
  pid_t pending_pid_{-1};   // The new PID observed after a change.
  std::chrono::steady_clock::time_point pending_pid_first_seen_{};

  std::atomic<pid_t>    observed_pid_{-1};
  std::atomic<uint64_t> restart_count_{0};
  bool restart_triggered_{false};
};

}  // namespace onvif

#endif  // SRC_PROTECT_PID_WATCHER_HPP_
