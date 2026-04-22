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

#include <cstddef>
#include <cstdint>
#include <string>

namespace onvif {

/**
 * MsrClient — minimal gRPC client for UniFi Media Server Recording (MSR).
 *
 * Talks HTTP/2 cleartext ("prior knowledge") to MSR's unary RPC service on
 * 127.0.0.1:7700 via libcurl+nghttp2.  The only method we use is
 * unifi.media_server.recording.v1.RecordingAPI.StoreSnapshots, which causes
 * MSR to persist a JPEG as a native UBV thumbnail owned by ms:unifi-streaming
 * and returns an id (e.g. "FC5F49CA68D4-1776861156551") that UniFi Protect's
 * UI serves via MSP TCP on port 7701 — indistinguishable from first-party
 * camera thumbnails.
 *
 * Thread-safe: StoreSnapshot() uses a fresh curl handle per call.
 */
class MsrClient {
 public:
  // url is the MSR base URL, e.g. "http://127.0.0.1:7700".
  explicit MsrClient(std::string url);

  // Calls RecordingAPI.StoreSnapshots with a single parameters entry
  // { mac, snapshot=jpeg }.  Returns the native snapshot id on success,
  // empty string on failure (network, gRPC error, or malformed response).
  std::string StoreSnapshot(const std::string& mac,
                            const void* jpeg, std::size_t jpeg_len);

 private:
  std::string url_;
};

namespace msr_client_internal {

// Exposed for unit tests: build a serialised StoreSnapshotsRequest protobuf
// (not yet wrapped in the 5-byte gRPC length-prefixed frame).
std::string build_store_request(const std::string& mac,
                                const void* jpeg, std::size_t jpeg_len);

// Exposed for unit tests: parse the inner StoreSnapshotsResponse message
// (after stripping the 5-byte gRPC prefix) and return the first result's id.
// Returns empty string on any parse error or if id is missing.
std::string parse_store_response(const void* msg, std::size_t msg_len);

}  // namespace msr_client_internal

}  // namespace onvif
