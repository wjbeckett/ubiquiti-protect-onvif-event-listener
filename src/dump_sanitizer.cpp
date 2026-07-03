// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#include "dump_sanitizer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace onvif {

namespace {

bool is_blank(const std::string& s) {
  for (char c : s) {
    if (!std::isspace(static_cast<unsigned char>(c))) return false;
  }
  return true;
}

// In-place literal find-and-replace.  Used for camera-name redaction
// where the search string may contain regex meta-characters and we
// don't want them interpreted.
void replace_all(std::string& s,
                  const std::string& needle,
                  const std::string& with) {
  if (needle.empty()) return;
  size_t pos = 0;
  while ((pos = s.find(needle, pos)) != std::string::npos) {
    s.replace(pos, needle.size(), with);
    pos += with.size();
  }
}

// FNV-1a 32-bit.  Deterministic across runs / machines and small
// enough to render as 8 hex characters.  Not cryptographic — the
// goal is to anonymise display, not to be irreversible against a
// dictionary attack.  A motivated reader with the original camera
// list could rehash and match, which is acceptable for diagnostics
// shared with the project owner.
std::string fnv1a_hex8(const std::string& s) {
  uint32_t h = 0x811c9dc5u;
  for (unsigned char c : s) {
    h ^= c;
    h *= 0x01000193u;
  }
  char buf[9];
  std::snprintf(buf, sizeof(buf), "%08x", h);
  return std::string(buf);
}

std::string camera_label(const std::string& name) {
  return "Camera-" + fnv1a_hex8(name);
}

// Deterministic short label for stable-hash redactions (MAC, Mongo ID,
// UUID).  Cross-line correlation in a dump still works because the same
// input always maps to the same 8-hex suffix, but the original value is
// gone.
std::string hash_label(const char* prefix, const std::string& value) {
  return std::string(prefix) + fnv1a_hex8(value);
}

}  // namespace

std::string DumpSanitizer::register_camera_name(const std::string& name) {
  if (name.empty() || is_blank(name)) return name;
  camera_names_.insert(name);
  return camera_label(name);
}

std::string DumpSanitizer::remap_ip(const std::string& ip) {
  auto cached = ip_cache_.find(ip);
  if (cached != ip_cache_.end()) return cached->second;

  unsigned int o[4];
  // sscanf with %u accepts leading zeros and signs; range-check below.
  if (std::sscanf(ip.c_str(), "%u.%u.%u.%u",
                  &o[0], &o[1], &o[2], &o[3]) != 4) {
    return ip;
  }
  for (unsigned int v : o) {
    if (v > 255) return ip;
  }

  std::vector<int> prefix;
  prefix.reserve(4);
  std::string result;
  for (int i = 0; i < 4; ++i) {
    const auto key = std::make_pair(prefix, static_cast<int>(o[i]));
    auto it = octet_at_prefix_.find(key);
    int mapped;
    if (it != octet_at_prefix_.end()) {
      mapped = it->second;
    } else {
      int& cnt = counters_[prefix];
      ++cnt;
      mapped = cnt;
      octet_at_prefix_[key] = mapped;
    }
    if (i > 0) result += '.';
    result += std::to_string(mapped);
    prefix.push_back(mapped);
  }
  ip_cache_[ip] = result;
  return result;
}

namespace {

// Iterate matches of @p re in @p in, calling @p replacer with each match
// to produce the replacement text.  Avoids regex_replace's lack of
// lambda support in C++17.
template <typename Replacer>
std::string regex_replace_with(const std::string& in,
                                const std::regex& re,
                                Replacer&& replacer) {
  std::string out;
  out.reserve(in.size());
  auto it  = std::sregex_iterator(in.begin(), in.end(), re);
  auto end = std::sregex_iterator();
  size_t last_pos = 0;
  for (; it != end; ++it) {
    const auto pos = static_cast<size_t>(it->position());
    out.append(in, last_pos, pos - last_pos);
    out += replacer(*it);
    last_pos = pos + static_cast<size_t>(it->length());
  }
  out.append(in, last_pos, std::string::npos);
  return out;
}

}  // namespace

std::string DumpSanitizer::sanitize(const std::string& in) {
  std::string out = in;

  // -------- Sentry DSN (must run before generic 32-hex + URL rules) --------
  // Format: https://<32-hex-token>@<subdomain>.ingest.sentry.io/<projectid>
  // Preserving just the host + project would still identify the tenant, so
  // we collapse the whole DSN.  A leaked DSN allows event injection into
  // Ubiquiti's Sentry.
  static const std::regex sentry_dsn_re(
      R"(https?://[0-9a-f]{32}@[^\s"'<>/]+\.ingest\.sentry\.io/\d+)",
      std::regex::icase);
  out = std::regex_replace(out, sentry_dsn_re, "[REDACTED_SENTRY_DSN]");

  // -------- IPv4 addresses --------
  // Word-bounded 4-octet pattern.  remap_ip() validates 0-255; out-of-
  // range matches are returned unchanged.
  static const std::regex ipv4_re(
      R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
  out = regex_replace_with(out, ipv4_re,
      [this](const std::smatch& m) { return remap_ip(m.str(0)); });

  // -------- WS-Security tag bodies --------
  static const std::regex wsse_user_re(
      R"(<wsse:Username[^>]*>[^<]*</wsse:Username>)");
  out = std::regex_replace(out, wsse_user_re,
      "<wsse:Username>[REDACTED]</wsse:Username>");

  static const std::regex wsse_pw_re(
      R"(<wsse:Password[^>]*>[^<]*</wsse:Password>)");
  out = std::regex_replace(out, wsse_pw_re,
      "<wsse:Password>[REDACTED]</wsse:Password>");

  static const std::regex wsse_nonce_re(
      R"(<wsse:Nonce[^>]*>[^<]*</wsse:Nonce>)");
  out = std::regex_replace(out, wsse_nonce_re,
      "<wsse:Nonce>[REDACTED]</wsse:Nonce>");

  // -------- key=value secrets (any quoting / unquoted) --------
  // Matches: password=foo, password = "foo bar", password='x', etc.
  // We deliberately keep the key + separator and replace just the
  // value so the format remains parseable.
  static const std::regex pw_kv_re(
      R"(((?:password|passwd|pwd)\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&"']+))",
      std::regex::icase);
  out = std::regex_replace(out, pw_kv_re, "$1[REDACTED]");

  static const std::regex user_kv_re(
      R"((\b(?:username|user)\s*=\s*)("[^"]*"|'[^']*'|[^\s,;&"']+))",
      std::regex::icase);
  out = std::regex_replace(out, user_kv_re, "$1[REDACTED]");

  // -------- URL credentials: scheme://user:pass@host --------
  // Handles http(s), rtsp(s), and rtmp URLs.  Third-party cameras store
  // their RTSP stream URL in Protect's cameras.channels / .sourceUrl
  // with credentials embedded (rtsp://user:pass@host:port/stream), and
  // those columns show up in cameras.json.
  static const std::regex url_creds_re(
      R"(((?:https?|rtsps?|rtmp)://)([^:/@\s]+):([^@\s]+)@)",
      std::regex::icase);
  out = std::regex_replace(out, url_creds_re,
      "$1[REDACTED]:[REDACTED]@");

  // -------- Authorization: Basic <base64> --------
  static const std::regex auth_basic_re(
      R"((Authorization:\s*Basic\s+)([A-Za-z0-9+/=]+))",
      std::regex::icase);
  out = std::regex_replace(out, auth_basic_re, "$1[REDACTED]");

  // -------- X-UserId header (Protect API auth bypass token) --------
  static const std::regex xuserid_re(
      R"((X-UserId:\s*)([A-Za-z0-9._\-]+))",
      std::regex::icase);
  out = std::regex_replace(out, xuserid_re, "$1[REDACTED]");

  // -------- Query-string session values ---------
  // Protect UI/API URLs carry per-request correlators (uniqid=ws-<uuid>,
  // requestId=<...>, sessionId=<uuid>) that fingerprint an install.  We
  // keep the key so URL structure stays parseable and blank the value.
  static const std::regex session_qs_re(
      R"(([?&](?:uniqid|requestId|sessionId))=([^&\s"'<>]+))",
      std::regex::icase);
  out = std::regex_replace(out, session_qs_re, "$1=[REDACTED]");

  // -------- Streaming path tokens ---------
  // wss://host/<12+ base62 chars>?... and tcp://host:port/<12+ base62 chars>
  // both appear in livestream redirect URLs in Protect's api.log.  The
  // path token is a session-scoped play secret that shouldn't leave the
  // install.  Field-observed: gleep52's dump on issue #34 carried 17 raw
  // tcp:// tokens because the earlier version of this rule only matched
  // wss?://.
  static const std::regex stream_path_re(
      R"(((?:wss?|tcp)://[^/\s"'<>]+/)([A-Za-z0-9]{12,}))",
      std::regex::icase);
  out = std::regex_replace(out, stream_path_re, "$1[REDACTED_WS_TOKEN]");

  // -------- UUIDs (36-char with dashes) ---------
  // 8-4-4-4-12 hex.  Ironclad accessId, sessionId payload values, Protect
  // livestream sessionIds, etc.  Stable-hashed so cross-line correlation
  // still works.
  static const std::regex uuid_re(
      R"(\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-)"
      R"([0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b)");
  out = regex_replace_with(out, uuid_re, [](const std::smatch& m) {
    return hash_label("uuid-", m.str(0));
  });

  // -------- 32-hex tokens (must run AFTER Sentry DSN) ---------
  // Sentry auth tokens, groupKeys, generic 128-bit secrets.  Word-bounded
  // with an explicit non-hex neighbour check because `\b` won't fire
  // against `_` (an ECMAScript regex word char).
  static const std::regex hex32_re(
      R"((^|[^0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F]))");
  out = regex_replace_with(out, hex32_re, [](const std::smatch& m) {
    return m.str(1) + "[REDACTED_HEX32]";
  });

  // -------- 24-hex Mongo-style IDs (must run BEFORE MAC bare 12-hex) ---
  // Protect cameraIds, userIds, eventIds, thumbnailIds.  Absorbing these
  // first ensures the MAC-bare rule below doesn't chew off the first 12
  // characters of a Mongo ID that happens to be lowercase.
  static const std::regex mongo_id_re(
      R"((^|[^0-9a-fA-F])([0-9a-fA-F]{24})(?![0-9a-fA-F]))");
  out = regex_replace_with(out, mongo_id_re, [](const std::smatch& m) {
    return m.str(1) + hash_label("id-", m.str(2));
  });

  // -------- MAC address, colon form ---------
  // AA:BB:CC:DD:EE:FF -- typically in Protect api.log request tags.
  static const std::regex mac_colon_re(
      R"((^|[^0-9A-Fa-f:])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?![0-9A-Fa-f:]))");
  out = regex_replace_with(out, mac_colon_re, [](const std::smatch& m) {
    return m.str(1) + hash_label("mac-", m.str(2));
  });

  // -------- MAC address, bare 12-hex ---------
  // F00000FDAED9 (in UBV paths, mst decode session tags, gRPC references).
  // Runs after 24-hex Mongo IDs, so any lowercase 12-hex chunk that was
  // part of a 24-hex ID is already redacted.  We stay case-insensitive
  // because 12-hex-uppercase is what UBV paths use but some Protect
  // components lowercase MACs before logging them.
  static const std::regex mac_bare_re(
      R"((^|[^0-9A-Fa-f])([0-9A-Fa-f]{12})(?![0-9A-Fa-f]))");
  out = regex_replace_with(out, mac_bare_re, [](const std::smatch& m) {
    return m.str(1) + hash_label("mac-", m.str(2));
  });

  // -------- Registered camera names --------
  // Substitute longest names first to avoid swallowing parts of longer
  // names ("Lincoln" within "Lincoln Doorbell").  Literal replacement so
  // names with regex meta-characters (apostrophes, parentheses, etc.)
  // work correctly.
  if (!camera_names_.empty()) {
    std::vector<std::string> by_len(
        camera_names_.begin(), camera_names_.end());
    std::sort(by_len.begin(), by_len.end(),
              [](const std::string& a, const std::string& b) {
                return a.size() > b.size();
              });
    for (const std::string& name : by_len) {
      replace_all(out, name, camera_label(name));
    }
  }

  return out;
}

}  // namespace onvif
