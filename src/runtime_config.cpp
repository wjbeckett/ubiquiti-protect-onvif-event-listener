// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#include "runtime_config.hpp"

#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "absl/flags/commandlineflag.h"
#include "absl/flags/reflection.h"
#include "absl/log/log.h"
#include "absl/status/status.h"

#include "unifi_camera_config.hpp"  // for internal::json_get

namespace runtime_config {

const std::vector<Entry>& Schema() {
  static const std::vector<Entry> kEntries = {
    // ---- Detection ----
    {"detect", Type::Bool,
     "Run NanoDet-M as a fallback when the camera supplies no ONVIF bbox.",
     "Detection"},
    {"detect_override", Type::Bool,
     "Always run NanoDet-M, ignoring the ONVIF bbox.  Implies --detect.",
     "Detection"},
    {"coalesce_window_sec", Type::Int,
     "Merge consecutive detections from the same camera within N seconds. "
     "Set to 0 to disable.",
     "Detection"},
    {"max_events_per_hour", Type::Int,
     "Per-camera detection rate limit per hour.  Set to 0 for unlimited.",
     "Detection"},
    {"coalesce_history", Type::Bool,
     "On startup, merge already-recorded events older than coalesce_window.",
     "Detection"},
    {"coalesce_history_days", Type::Int,
     "How far back to scan during the startup coalesce pass.",
     "Detection"},
    {"default_object_type", Type::String,
     "Default object type for events that arrive without a class "
     "(e.g. 'motion', 'person', 'vehicle').",
     "Detection"},
    {"camera_object_types", Type::String,
     "Per-camera type overrides as comma-separated ip=type pairs, e.g. "
     "192.168.1.108=person,192.168.1.109=vehicle.",
     "Detection"},

    // ---- First-party cameras ----
    {"first_party_cameras", Type::String,
     "Comma-separated camera IDs to enable smart-detect for.  Use the "
     "tickbox list above to manage this.",
     "First-party cameras"},
    {"first_party_camera_models", Type::String,
     "Comma-separated model substrings to match (e.g. G3 Instant,G4 Bullet).",
     "First-party cameras"},
    {"poll_interval_sec", Type::Int,
     "Seconds between motion-event poll cycles for first-party cameras.",
     "First-party cameras"},

    // ---- Cameras ----
    {"rtsp_audio", Type::String,
     "Set to 'enable' or 'disable' to flip RTSP audio on every "
     "audio-capable camera at startup.  Empty leaves the existing setting "
     "alone.",
     "Cameras"},

    // ---- MSR forwarding ----
    {"msr_url", Type::String,
     "Base URL of the local MSR gRPC service.  Default works on Dream "
     "Routers / NVRs out of the box; set to empty string to disable MSR "
     "thumbnail forwarding (third-party thumbnails will be stored in the "
     "DB only).",
     "MSR forwarding"},
    {"backfill_apply", Type::Bool,
     "When true, the startup MSR-thumbnail backfill writes changes.  Set "
     "to false for a dry-run that logs what would be migrated without "
     "touching MSR or the events table.",
     "MSR forwarding"},

    // ---- Logging ----
    {"verbose", Type::Bool,
     "Verbose log level (INFO and above).  Disabled by default writes only "
     "errors.",
     "Logging"},
  };
  return kEntries;
}

namespace {

// Escape @p s for embedding inside a JSON string literal.
std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 2);
  for (char c : s) {
    switch (c) {
      case '"':  out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n";  break;
      case '\r': out += "\\r";  break;
      case '\t': out += "\\t";  break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", c);
          out += buf;
        } else {
          out += c;
        }
    }
  }
  return out;
}

std::string read_file(const std::string& path) {
  std::ifstream f(path);
  if (!f.is_open()) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

}  // namespace

int LoadFromFile(const std::string& path) {
  const std::string content = read_file(path);
  if (content.empty()) return 0;

  int applied = 0;
  for (const auto& e : Schema()) {
    const std::string raw = unifi::internal::json_get(content, e.name);
    if (raw.empty()) continue;  // not set, or explicitly empty
    auto* flag = absl::FindCommandLineFlag(e.name);
    if (flag == nullptr) {
      LOG(WARNING) << "[config] unknown flag: " << e.name;
      continue;
    }
    std::string err;
    if (!flag->ParseFrom(raw, &err)) {
      LOG(WARNING) << "[config] " << e.name << "=" << raw
                   << " rejected: " << err;
      continue;
    }
    LOG(INFO) << "[config] override " << e.name << "=" << raw;
    ++applied;
  }
  return applied;
}

std::map<std::string, std::string> ReadFromFile(const std::string& path) {
  std::map<std::string, std::string> out;
  const std::string content = read_file(path);
  for (const auto& e : Schema()) {
    out[e.name] = content.empty()
        ? std::string()
        : unifi::internal::json_get(content, e.name);
  }
  return out;
}

absl::Status WriteToFile(const std::string& path,
                         const std::map<std::string, std::string>& values) {
  std::string out = "{\n";
  bool first = true;
  for (const auto& e : Schema()) {
    if (!first) out += ",\n";
    first = false;
    auto it = values.find(e.name);
    const std::string v = (it != values.end()) ? it->second : std::string();
    out += "  \"";
    out += e.name;
    out += "\": \"";
    out += json_escape(v);
    out += "\"";
  }
  out += "\n}\n";

  const std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp);
    if (!f.is_open())
      return absl::InternalError("cannot open " + tmp + " for write");
    f << out;
    if (!f.good())
      return absl::InternalError("write failed for " + tmp);
  }
  if (std::rename(tmp.c_str(), path.c_str()) != 0)
    return absl::InternalError("rename " + tmp + " -> " + path + " failed");
  return absl::OkStatus();
}

}  // namespace runtime_config
