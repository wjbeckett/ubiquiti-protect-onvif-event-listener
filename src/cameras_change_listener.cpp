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

#include "cameras_change_listener.hpp"

#include <libpq-fe.h>
#include <sys/select.h>

#include <chrono>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/log/log.h"

namespace onvif {

namespace {

constexpr const char* kChannel = "onvif_recorder_camera_change";

// CREATE OR REPLACE both the function and the trigger so a Protect package
// upgrade that recreates the schema can be recovered by the next recorder
// start-up.  Fires on UPDATE only when featureFlags or smartDetectSettings
// actually changes -- avoids waking us for unrelated columns (lastSeen,
// stats, etc.) that change continuously.
constexpr const char* kTriggerFnSql = R"(
CREATE OR REPLACE FUNCTION onvif_recorder_camera_change_notify()
  RETURNS TRIGGER
  LANGUAGE plpgsql
  AS $body$
BEGIN
  PERFORM pg_notify('onvif_recorder_camera_change', NEW.id);
  RETURN NULL;
END;
$body$;
)";

constexpr const char* kTriggerDropSql =
"DROP TRIGGER IF EXISTS onvif_recorder_camera_change ON cameras";

// Cast json -> jsonb in the WHEN clause: Protect stores these columns
// as `json`, which has no equality operator (so IS DISTINCT FROM rejects
// it).  Casting to jsonb yields a stable canonical form for comparison
// and lets the trigger fire only when the value actually changed.
constexpr const char* kTriggerCreateSql = R"(
CREATE TRIGGER onvif_recorder_camera_change
  AFTER UPDATE ON cameras
  FOR EACH ROW
  WHEN (OLD."featureFlags"::jsonb        IS DISTINCT FROM NEW."featureFlags"::jsonb
     OR OLD."smartDetectSettings"::jsonb IS DISTINCT FROM NEW."smartDetectSettings"::jsonb)
  EXECUTE FUNCTION onvif_recorder_camera_change_notify();
)";

// Build the libpq conninfo string from a DbConfig, mirroring
// unifi::internal::build_connstr's layout (which is in an anonymous
// namespace there).
std::string build_connstr(const unifi::DbConfig& db) {
  std::string s =
    "host="    + db.host +
    " port="   + std::to_string(db.port) +
    " dbname=" + db.dbname +
    " user="   + db.user;
  if (!db.password.empty())
    s += " password=" + db.password;
  return s;
}

}  // namespace

CamerasChangeListener::CamerasChangeListener(
    unifi::DbConfig db,
    std::set<std::string> managed_camera_ids,
    unifi::CameraChangeLog* change_log)
    : db_(std::move(db)),
      managed_camera_ids_(std::move(managed_camera_ids)),
      change_log_(change_log) {}  // NOLINT(whitespace/indent_namespace)

CamerasChangeListener::~CamerasChangeListener() { stop(); }

void CamerasChangeListener::add_managed_camera(const std::string& id) {
  if (id.empty()) return;
  std::lock_guard<std::mutex> lk(managed_mu_);
  managed_camera_ids_.insert(id);
}

absl::Status CamerasChangeListener::install_trigger(void* pg_conn) {
  PGconn* conn = static_cast<PGconn*>(pg_conn);

  PGresult* r = PQexec(conn, kTriggerFnSql);
  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
    std::string err = PQresultErrorMessage(r);
    PQclear(r);
    return absl::InternalError("install_trigger: function: " + err);
  }
  PQclear(r);

  r = PQexec(conn, kTriggerDropSql);
  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
    std::string err = PQresultErrorMessage(r);
    PQclear(r);
    return absl::InternalError("install_trigger: drop: " + err);
  }
  PQclear(r);

  r = PQexec(conn, kTriggerCreateSql);
  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
    std::string err = PQresultErrorMessage(r);
    PQclear(r);
    return absl::InternalError("install_trigger: create: " + err);
  }
  PQclear(r);

  return absl::OkStatus();
}

absl::Status CamerasChangeListener::start() {
  if (running_.exchange(true))
    return absl::FailedPreconditionError("listener already running");

  // Install the trigger via a one-shot connection.  Connection issues at
  // this stage are fatal for the listener -- the caller logs the error;
  // the recorder still functions, just without reactive re-flips.
  PGconn* setup = PQconnectdb(build_connstr(db_).c_str());
  if (!setup || PQstatus(setup) != CONNECTION_OK) {
    std::string err = setup ? PQerrorMessage(setup) : "PQconnectdb returned null";
    if (setup) PQfinish(setup);
    running_.store(false);
    return absl::InternalError("cameras_change_listener connect: " + err);
  }
  auto status = install_trigger(setup);
  PQfinish(setup);
  if (!status.ok()) {
    running_.store(false);
    return status;
  }

  thread_ = std::thread([this] { run(); });
  return absl::OkStatus();
}

void CamerasChangeListener::stop() {
  if (!running_.exchange(false)) return;
  if (thread_.joinable()) thread_.join();
}

void CamerasChangeListener::run() {
  LOG(INFO) << "[cameras_listener] starting";

  while (running_) {
    PGconn* conn = PQconnectdb(build_connstr(db_).c_str());
    if (!conn || PQstatus(conn) != CONNECTION_OK) {
      LOG(WARNING) << "[cameras_listener] connect failed: "
                   << (conn ? PQerrorMessage(conn) : "null conn")
                   << "; retrying in 30s";
      if (conn) PQfinish(conn);
      for (int i = 0; i < 30 && running_; ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }

    PGresult* r = PQexec(conn, "LISTEN onvif_recorder_camera_change");
    if (PQresultStatus(r) != PGRES_COMMAND_OK) {
      LOG(WARNING) << "[cameras_listener] LISTEN failed: "
                   << PQresultErrorMessage(r) << "; reconnecting in 30s";
      PQclear(r);
      PQfinish(conn);
      for (int i = 0; i < 30 && running_; ++i)
        std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }
    PQclear(r);
    LOG(INFO) << "[cameras_listener] LISTEN " << kChannel << " active";

    const int sock = PQsocket(conn);

    while (running_) {
      // Block until the socket is readable or the 1 s timeout fires.
      // The 1 s tick lets us promptly notice stop().
      fd_set rfds;
      FD_ZERO(&rfds);
      FD_SET(sock, &rfds);
      timeval tv{1, 0};
      int rc = ::select(sock + 1, &rfds, nullptr, nullptr, &tv);
      if (rc < 0) break;  // EINTR or worse; reconnect.

      if (!PQconsumeInput(conn)) {
        LOG(WARNING) << "[cameras_listener] PQconsumeInput failed: "
                     << PQerrorMessage(conn) << "; reconnecting";
        break;
      }

      PGnotify* n = nullptr;
      while ((n = PQnotifies(conn)) != nullptr) {
        const std::string cam_id = n->extra ? n->extra : std::string();
        PQfreemem(n);
        notify_count_.fetch_add(1);
        if (cam_id.empty()) continue;

        bool managed = false;
        {
          std::lock_guard<std::mutex> lk(managed_mu_);
          managed = managed_camera_ids_.count(cam_id) > 0;
        }
        if (!managed) continue;

        // Re-flip via the public single-camera vector form.  Idempotent --
        // a row that already matches the expected shape is left alone by
        // the underlying UPDATE's WHERE clause.
        unifi::FirstPartyCamera fpc;
        fpc.id = cam_id;
        std::vector<unifi::FirstPartyCamera> one{fpc};
        auto s = unifi::enable_smart_detect(one, db_, change_log_);
        if (!s.ok()) {
          LOG(WARNING) << "[cameras_listener] re-flip "
                       << cam_id << ": " << s.message();
        } else {
          reflip_count_.fetch_add(1);
          LOG(INFO) << "[cameras_listener] re-flipped featureFlags for "
                    << cam_id;
        }
      }
    }
    PQfinish(conn);
  }

  LOG(INFO) << "[cameras_listener] stopped";
}

}  // namespace onvif
