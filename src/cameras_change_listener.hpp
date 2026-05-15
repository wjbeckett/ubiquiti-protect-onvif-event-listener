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

#ifndef SRC_CAMERAS_CHANGE_LISTENER_HPP_
#define SRC_CAMERAS_CHANGE_LISTENER_HPP_

#include <atomic>
#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <thread>

#include "absl/status/status.h"
#include "camera_change_log.hpp"
#include "unifi_camera_config.hpp"

namespace onvif {

/**
 * CameraChangeListener — re-flips featureFlags when Protect clobbers them.
 *
 * Protect's controller re-syncs every camera row from the device's reported
 * capabilities on its own start-up (and on various camera lifecycle events
 * like adoption / reconnect), which resets featureFlags.smartDetectTypes
 * back to []  for cameras whose firmware does not natively advertise
 * smart-detect (e.g. G3 Dome).  The onvif-recorder's start-up
 * enable_smart_detect runs once and is then liable to be overwritten by
 * the Protect controller as soon as it finishes its own start sequence.
 *
 * This listener uses Postgres LISTEN/NOTIFY to react the *moment* Protect
 * writes to the cameras row, instead of polling.  A single trigger on the
 * cameras table fires NOTIFY 'onvif_recorder_camera_change' with the
 * camera id whenever featureFlags or smartDetectSettings changes.  We
 * listen on a persistent connection; on each notification, if the camera
 * id is in the managed set, we re-run enable_smart_detect on just that
 * camera.
 *
 * Pairs with ProtectPidWatcher (which handles the larger "Protect just
 * restarted, take ourselves down so the next start-up reconciles
 * everything cleanly" case) -- this listener is the reactive half for
 * the cases where Protect writes to a single camera without restarting.
 */
class CamerasChangeListener {
 public:
  CamerasChangeListener(unifi::DbConfig db,
                        std::set<std::string> managed_camera_ids,
                        unifi::CameraChangeLog* change_log);
  ~CamerasChangeListener();

  CamerasChangeListener(const CamerasChangeListener&) = delete;
  CamerasChangeListener& operator=(const CamerasChangeListener&) = delete;

  // Install the PG trigger that fires NOTIFY on cameras.featureFlags or
  // .smartDetectSettings changes, then begin the listener thread.  Idempotent
  // -- the trigger is CREATE OR REPLACE-d on every start so it self-heals
  // after a Protect package upgrade that recreates the schema.
  //
  // Returns OkStatus on success; on trigger-install failure returns the
  // error and the thread is not started.
  absl::Status start();

  // Stop the listener.  Idempotent.
  void stop();

  // Add a camera id to the managed set at runtime (e.g. after the rescan
  // thread hot-adds a third-party camera).  Thread-safe.
  void add_managed_camera(const std::string& id);

  // Visible for testing.
  uint64_t notify_count_for_testing() const { return notify_count_.load(); }
  uint64_t reflip_count_for_testing() const { return reflip_count_.load(); }

  // Install the trigger on an arbitrary connection.  Exposed for testing
  // against an embedded PG.  Idempotent.
  static absl::Status install_trigger(void* pg_conn);

 private:
  void run();

  unifi::DbConfig db_;

  mutable std::mutex managed_mu_;
  std::set<std::string> managed_camera_ids_;  // GUARDED_BY(managed_mu_)

  unifi::CameraChangeLog* change_log_;

  std::thread thread_;
  std::atomic<bool> running_{false};

  std::atomic<uint64_t> notify_count_{0};
  std::atomic<uint64_t> reflip_count_{0};
};

}  // namespace onvif

#endif  // SRC_CAMERAS_CHANGE_LISTENER_HPP_
