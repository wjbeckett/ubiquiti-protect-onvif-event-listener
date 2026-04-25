// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#include "dump_sanitizer.hpp"

#include <cstdio>
#include <regex>
#include <string>
#include <utility>
#include <vector>

namespace onvif {

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
  static const std::regex url_creds_re(
      R"((https?://)([^:/@\s]+):([^@\s]+)@)",
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

  return out;
}

}  // namespace onvif
