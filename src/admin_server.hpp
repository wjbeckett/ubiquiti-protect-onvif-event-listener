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

#include <cstdint>
#include <string>

#include "unifi_camera_config.hpp"

struct MHD_Daemon;

namespace onvif {

/// Minimal HTTP server that exposes an admin page + JSON API for managing the
/// onvif-recorder Debian package: force-check-for-updates, switch APT channel,
/// toggle auto-update, uninstall.
///
/// Listens on 127.0.0.1:@p port (loopback only).  The nginx reverse proxy on
/// the UniFi OS router forwards authenticated requests from /onvif/admin/ to
/// this server.
///
/// All mutating endpoints shell out to `systemctl` / `apt-get`, so the server
/// must run as root (same as the recorder binary does today).
class AdminServer {
 public:
  /// Start the server.  Returns false on failure.
  ///
  /// @p channel_file is the path to /etc/onvif-recorder/channel (may be empty
  /// for testing to disable channel switching).
  /// @p version is the version string reported by /api/status.
  /// Pass @p port == 0 to let the OS pick an ephemeral port (tests);
  /// the chosen port is then available via port().
  bool start(const std::string& version,
             const std::string& channel_file,
             uint16_t port = 7891,
             const std::string& config_path = "/etc/onvif-recorder/config.json",
             const unifi::DbConfig& db = unifi::DbConfig{},
             const std::string& protect_url = "",
             const std::string& protect_user_id = "");

  /// Return the port the server is listening on. Only meaningful after a
  /// successful start().  Useful when start() was called with port=0.
  uint16_t port() const { return port_; }

  /// Stop the server and release the listening socket.
  void stop();

  ~AdminServer();

  AdminServer() = default;
  AdminServer(const AdminServer&)            = delete;
  AdminServer& operator=(const AdminServer&) = delete;

 private:
  ::MHD_Daemon* daemon_{nullptr};
  std::string version_;
  std::string channel_file_;
  std::string config_path_;
  unifi::DbConfig db_;
  std::string protect_url_;
  std::string protect_user_id_;
  uint16_t port_{0};
};

}  // namespace onvif
