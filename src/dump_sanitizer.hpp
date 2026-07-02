// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#ifndef SRC_DUMP_SANITIZER_HPP_
#define SRC_DUMP_SANITIZER_HPP_

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace onvif {

// Sanitises text destined for a publicly-shareable diagnostic archive.
// One instance is shared across every file in a single dump so that the
// same source IP / credential / token maps to the same redacted value
// across files (e.g. journal.log and camera_health.json line up).
//
// What it does:
//   - IPv4 addresses are remapped via a per-prefix counter trie:
//       192.168.1.1   -> 1.1.1.1
//       192.168.1.2   -> 1.1.1.2  (last octet differs from first IP)
//       192.168.2.100 -> 1.1.2.1  (third octet differs, last octet is
//                                  the first under that new prefix)
//     Out-of-range octets (>255) and non-IPv4 4-dot patterns (e.g.
//     package versions like "1.0.0.0") are left untouched.
//   - WS-Security <wsse:Username> / <wsse:Password> / <wsse:Nonce>
//     bodies are replaced with [REDACTED].
//   - "password=...", "passwd=...", "user=..." key-value pairs (in
//     any quoting form) get the value replaced with [REDACTED].
//   - HTTP basic credentials embedded in URLs (scheme://user:pass@host)
//     and "Authorization: Basic <b64>" headers are replaced.
//   - "X-UserId: <id>" and similar ID headers are replaced.
//   - Sentry DSN URLs (https://<token>@<host>.ingest.sentry.io/<proj>)
//     are collapsed to [REDACTED_SENTRY_DSN] before the URL / 32-hex
//     rules run so nothing partial leaks.
//   - Query-string session correlators (?uniqid=, requestId=,
//     sessionId=) get their values blanked.
//   - WebSocket path tokens (wss://host/<12+ base62 chars>) get the
//     token portion replaced with [REDACTED_WS_TOKEN].
//   - UUIDs (36-char 8-4-4-4-12 form), 24-hex Mongo-style IDs, and
//     bare or colon-form MAC addresses are replaced with stable
//     FNV-1a hash labels (uuid-<8hex> / id-<8hex> / mac-<8hex>) so
//     cross-line correlation still works in a redacted dump while
//     the original identifiers never leave the sanitiser.
//   - Any 32-hex bare token (Sentry token, groupKey, generic 128-bit
//     secret) becomes [REDACTED_HEX32].
//   - User-given camera names that the caller has registered via
//     register_camera_name() are replaced with a deterministic
//     "Camera-<8hex>" hash of the name.  Names are personally
//     identifying (people use real room / family names) and leak
//     through both JSON outputs (camera_health.json,
//     recent_events.json) and the journal log.  Hashing rather than
//     keeping a name->label map means original names never sit in
//     memory longer than the call that registers them.
class DumpSanitizer {
 public:
  // Returns the sanitised version of @p in.  Stateful: subsequent
  // calls reuse the same IP, credential, and camera-name mappings.
  std::string sanitize(const std::string& in);

  // Test seam: explicitly remap an IPv4 address and return the result.
  // Returns @p ip unchanged if it doesn't parse as a 0-255 quad.
  std::string remap_ip(const std::string& ip);

  // Register a camera name to redact.  Returns the anonymised label
  // ("Camera-<8 hex chars of FNV-1a of name>") that subsequent
  // sanitize() calls will substitute every occurrence of @p name
  // with.  Deterministic across runs and machines so dumps from the
  // same device line up.  No-op for empty / whitespace-only names.
  std::string register_camera_name(const std::string& name);

 private:
  // Per-prefix counter trie: at each octet position, a counter is
  // associated with the path of MAPPED octets seen so far.  When a
  // never-before-seen original octet appears under that prefix, the
  // counter is incremented and the new value becomes the mapping.
  std::map<std::vector<int>, int> counters_;
  std::map<std::pair<std::vector<int>, int>, int> octet_at_prefix_;

  // Cache of fully-resolved IP -> sanitised IP for repeat lookups.
  std::map<std::string, std::string> ip_cache_;

  // Set of registered camera names.  Iterated in sanitize() and
  // substituted literally (not as regex) with their deterministic
  // hash label, longest first to avoid substring collisions
  // ("Lincoln" inside "Lincoln Doorbell").
  std::set<std::string> camera_names_;
};

}  // namespace onvif

#endif  // SRC_DUMP_SANITIZER_HPP_
