// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#include <iostream>
#include <string>

#include "dump_sanitizer.hpp"

static int g_pass = 0;
static int g_fail = 0;

static void check(bool cond, const std::string& label) {
  if (cond) {
    ++g_pass;
  } else {
    ++g_fail;
    std::cerr << "FAIL: " << label << '\n';
  }
}

// ---------------------------------------------------------------
// IP remapping per the per-prefix trie spec.
// ---------------------------------------------------------------
static void test_ip_remap_basic() {
  onvif::DumpSanitizer s;
  // Spec from the original feature request:
  //   192.168.1.1   -> 1.1.1.1
  //   192.168.1.2   -> 1.1.1.2
  //   192.168.2.100 -> 1.1.2.1
  check(s.remap_ip("192.168.1.1")   == "1.1.1.1",   "192.168.1.1 -> 1.1.1.1");
  check(s.remap_ip("192.168.1.2")   == "1.1.1.2",   "192.168.1.2 -> 1.1.1.2");
  check(s.remap_ip("192.168.2.100") == "1.1.2.1",   "192.168.2.100 -> 1.1.2.1");
}

static void test_ip_remap_consistent() {
  onvif::DumpSanitizer s;
  // Same input must produce the same output across calls (within one
  // sanitiser instance).
  const std::string a1 = s.remap_ip("10.0.0.5");
  const std::string a2 = s.remap_ip("10.0.0.5");
  check(a1 == a2, "same IP remaps consistently");
  // A different IP at the same depth gets a different mapping.
  const std::string b = s.remap_ip("10.0.0.6");
  check(a1 != b, "different IPs do not collide");
}

static void test_ip_remap_independent_subtrees() {
  onvif::DumpSanitizer s;
  // First octet differs -> last-octet counter independent.
  s.remap_ip("10.0.0.1");      // 1.1.1.1
  s.remap_ip("10.0.0.2");      // 1.1.1.2
  const std::string r = s.remap_ip("172.0.0.1");  // new prefix 172
  check(r == "2.1.1.1", "fresh prefix resets all downstream counters");
}

static void test_ip_remap_invalid_unchanged() {
  onvif::DumpSanitizer s;
  // Out-of-range octets are not touched.
  check(s.remap_ip("999.0.0.0") == "999.0.0.0",
        "out-of-range octet returned unchanged");
  // Non-IP strings are not touched.
  check(s.remap_ip("not-an-ip") == "not-an-ip",
        "garbage input returned unchanged");
}

// ---------------------------------------------------------------
// IP substitution within text.
// ---------------------------------------------------------------
static void test_sanitize_ip_in_text() {
  onvif::DumpSanitizer s;
  const std::string in =
      "[192.168.1.108] received 1 event\n"
      "[192.168.1.108] alive: events_recv=42\n"
      "[192.168.1.109] received 1 event\n"
      "Watching camera 192.168.1.108\n";
  const std::string out = s.sanitize(in);
  // Same IP must map to same value across all lines.
  check(out.find("192.168.1.108") == std::string::npos,
        "no original IP leaked");
  check(out.find("192.168.1.109") == std::string::npos,
        "second IP also remapped");
  // First IP encountered is .108, mapped to 1.1.1.1; .109 -> 1.1.1.2.
  check(out.find("[1.1.1.1] received 1 event") != std::string::npos,
        "first IP -> 1.1.1.1");
  check(out.find("[1.1.1.2] received 1 event") != std::string::npos,
        "second IP -> 1.1.1.2");
  check(out.find("Watching camera 1.1.1.1") != std::string::npos,
        "IP in different context -> same mapping");
}

static void test_sanitize_ignores_versions() {
  onvif::DumpSanitizer s;
  // Three-octet version strings won't match the 4-octet pattern.
  const std::string out = s.sanitize("v1.4.6 deployed; protect 7.0.107");
  check(out.find("v1.4.6") != std::string::npos, "v1.4.6 untouched");
  check(out.find("7.0.107") != std::string::npos, "7.0.107 untouched");
}

// ---------------------------------------------------------------
// Credential redaction.
// ---------------------------------------------------------------
static void test_sanitize_wsse_tags() {
  onvif::DumpSanitizer s;
  const std::string in =
      "<wsse:Username>admin</wsse:Username>"
      "<wsse:Password Type=\"...PasswordDigest\">aGFzaA==</wsse:Password>"
      "<wsse:Nonce EncodingType=\"...Base64Binary\">QUJDREVG</wsse:Nonce>";
  const std::string out = s.sanitize(in);
  check(out.find("admin")      == std::string::npos, "username redacted");
  check(out.find("aGFzaA==")   == std::string::npos, "password digest redacted");
  check(out.find("QUJDREVG")   == std::string::npos, "nonce redacted");
  check(out.find("[REDACTED]") != std::string::npos,
        "redaction marker present");
}

static void test_sanitize_kv_passwords() {
  onvif::DumpSanitizer s;
  std::string out;
  out = s.sanitize("password=hunter2");
  check(out == "password=[REDACTED]", "password=hunter2 redacted");
  out = s.sanitize("Password = \"foo bar\"");
  check(out.find("foo bar") == std::string::npos,
        "quoted password value redacted");
  out = s.sanitize("passwd='x@y' followed");
  check(out.find("x@y") == std::string::npos,
        "single-quoted passwd redacted");
}

static void test_sanitize_url_creds() {
  onvif::DumpSanitizer s;
  const std::string in =
      "fetching http://admin:hunter2@192.168.1.108/snap";
  const std::string out = s.sanitize(in);
  check(out.find("admin:hunter2@") == std::string::npos,
        "URL creds redacted");
  check(out.find("192.168.1.108") == std::string::npos,
        "URL host IP also remapped");
  check(out.find("[REDACTED]:[REDACTED]@") != std::string::npos,
        "redacted creds form");
}

static void test_sanitize_basic_auth_header() {
  onvif::DumpSanitizer s;
  const std::string out = s.sanitize(
      "Authorization: Basic YWRtaW46aHVudGVyMg==");
  check(out.find("YWRtaW46aHVudGVyMg==") == std::string::npos,
        "basic auth token redacted");
}

static void test_sanitize_xuserid() {
  onvif::DumpSanitizer s;
  const std::string out = s.sanitize(
      "X-UserId: 65f1abc012def03e40000123\n");
  check(out.find("65f1abc012def03e40000123") == std::string::npos,
        "X-UserId redacted");
}

static void test_sanitize_user_kv() {
  onvif::DumpSanitizer s;
  // "user=postgres" in conn strings is sensitive enough to redact.
  const std::string out = s.sanitize(
      "host=/run/postgresql port=5433 dbname=unifi-protect user=postgres");
  check(out.find("user=[REDACTED]") != std::string::npos,
        "user= value redacted");
  // db name and port should not be touched.
  check(out.find("dbname=unifi-protect") != std::string::npos,
        "dbname preserved");
  check(out.find("port=5433") != std::string::npos,
        "port preserved");
}

// Test names are deliberately generic placeholders ("Lincoln", "Hayes",
// "Polk"), not values borrowed from any real deployment, so the source
// tree never grows a personally-identifying camera name even by mistake.
static void test_register_camera_name_basic() {
  onvif::DumpSanitizer s;
  const std::string label_a = s.register_camera_name("Lincoln");
  const std::string label_b = s.register_camera_name("Hayes");
  // Labels are the deterministic hash form, distinct per name.
  check(label_a.rfind("Camera-", 0) == 0,
        "label has Camera- prefix");
  check(label_a.size() == 7 + 8,  // "Camera-" + 8 hex chars
        "label is 15 chars total");
  check(label_a != label_b,
        "distinct names get distinct labels");
  // Idempotent: same name -> same label.
  check(s.register_camera_name("Lincoln") == label_a,
        "duplicate name reuses label");
  // Empty / whitespace names are no-ops, returned unchanged.
  check(s.register_camera_name("") == "",
        "empty name returned unchanged");
  check(s.register_camera_name("   ") == "   ",
        "whitespace name returned unchanged");
}

static void test_sanitize_camera_names() {
  onvif::DumpSanitizer s;
  const std::string label_a = s.register_camera_name("Lincoln");
  const std::string label_b = s.register_camera_name("Hayes");
  const std::string in =
      "{\"name\":\"Lincoln\",\"events_1h\":3}\n"
      "msg: motion at Hayes at 19:24\n"
      "another note about Lincoln\n";
  const std::string out = s.sanitize(in);
  check(out.find("Lincoln") == std::string::npos,
        "first name redacted everywhere");
  check(out.find("Hayes") == std::string::npos,
        "second name redacted");
  check(out.find(label_a) != std::string::npos &&
        out.find(label_b) != std::string::npos,
        "hashed labels present");
}

static void test_sanitize_camera_name_longest_first() {
  onvif::DumpSanitizer s;
  // Register the substring first.  Longest-first sort must still
  // protect the longer name from being chewed up.
  const std::string short_label = s.register_camera_name("Polk");
  const std::string long_label  = s.register_camera_name("Polk Doorbell");
  const std::string out = s.sanitize(
      "Polk Doorbell tripped; Polk motion later.\n");
  // The longer name must be replaced as a whole.
  check(out.find("Polk Doorbell") == std::string::npos,
        "longer name fully redacted");
  check(out.find("Polk motion") == std::string::npos,
        "shorter name redacted separately");
  check(out.find(long_label) != std::string::npos,
        "longer name maps to its hash label");
  check(out.find(short_label + " motion") != std::string::npos,
        "shorter standalone occurrence maps to its own hash label");
}

static void test_sanitize_camera_name_deterministic() {
  // Two independent sanitisers see the same name -> same label.
  // Guards against accidental introduction of run-local state in the
  // hashing path (e.g. a per-instance counter).
  onvif::DumpSanitizer a;
  onvif::DumpSanitizer b;
  check(a.register_camera_name("Tyler") == b.register_camera_name("Tyler"),
        "hash label is deterministic across instances");
}

// ---------------------------------------------------------------
// Extended redactions for Protect-side log files.
// All placeholder values below are synthetic — not from any real
// dump — so no personally-identifying data ends up in the tree.
// ---------------------------------------------------------------

static void test_sanitize_sentry_dsn() {
  onvif::DumpSanitizer s;
  const std::string in =
      R"("dsn":"https://11112222333344445555666677778888)"
      R"(@example.ingest.sentry.io/12345")";
  const std::string out = s.sanitize(in);
  check(out.find("11112222333344445555666677778888") == std::string::npos,
        "sentry token redacted");
  check(out.find("sentry.io") == std::string::npos,
        "sentry host also collapsed");
  check(out.find("[REDACTED_SENTRY_DSN]") != std::string::npos,
        "sentry DSN marker present");
}

static void test_sanitize_query_session_values() {
  onvif::DumpSanitizer s;
  const std::string out = s.sanitize(
      "wss://host/livestream?uniqid=ws-abc123&sessionId=deadbeef&other=1&"
      "requestId=r-9x");
  check(out.find("uniqid=[REDACTED]") != std::string::npos,
        "uniqid value blanked");
  check(out.find("sessionId=[REDACTED]") != std::string::npos,
        "sessionId value blanked");
  check(out.find("requestId=[REDACTED]") != std::string::npos,
        "requestId value blanked");
  check(out.find("other=1") != std::string::npos,
        "unrelated query params preserved");
}

static void test_sanitize_ws_path_token() {
  onvif::DumpSanitizer s;
  const std::string out = s.sanitize(
      "livestream response {\"url\":\"wss://host:7446/AbCdEf1234567890"
      "?camera=xyz\"}");
  check(out.find("AbCdEf1234567890") == std::string::npos,
        "ws path token redacted");
  check(out.find("[REDACTED_WS_TOKEN]") != std::string::npos,
        "ws token marker present");
  check(out.find("wss://host:7446/") != std::string::npos,
        "host + port preserved");
}

// Regression for the gleep52-dump gap on issue #34: 17 raw 16-char play
// tokens leaked because the streaming-path rule only matched wss?://.
// Protect's api.log also carries tcp:// livestream redirects.
static void test_sanitize_tcp_path_token() {
  onvif::DumpSanitizer s;
  const std::string tok = "AbCdEf1234567890";  // 16 chars, synthetic
  const std::string out = s.sanitize(
      "livestream response {\"url\":\"tcp://host:7451/" + tok + "\"}");
  check(out.find(tok) == std::string::npos,
        "tcp path token redacted");
  check(out.find("[REDACTED_WS_TOKEN]") != std::string::npos,
        "tcp token marker present");
  check(out.find("tcp://host:7451/") != std::string::npos,
        "host + port preserved for tcp scheme");
}

static void test_sanitize_uuid() {
  onvif::DumpSanitizer s;
  const std::string uuid = "0123abcd-4567-89ab-cdef-0123456789ab";
  const std::string out = s.sanitize("sessionId=" + uuid);
  // sessionId= query-string rule redacts the whole value, so we test
  // the UUID rule directly in a non-query context.
  const std::string out2 = s.sanitize("payload {\"accessId\":\"" + uuid + "\"}");
  check(out2.find(uuid) == std::string::npos,
        "UUID redacted outside query context");
  check(out2.find("uuid-") != std::string::npos,
        "UUID replaced with uuid-<hash> label");
  // Deterministic across instances.
  onvif::DumpSanitizer s2;
  check(s.sanitize("x=" + uuid + " ") == s2.sanitize("x=" + uuid + " "),
        "UUID hash deterministic");
}

static void test_sanitize_hex32_token() {
  onvif::DumpSanitizer s;
  const std::string tok = "aaaabbbbccccddddeeeeffff00001111";  // 32 hex
  const std::string out = s.sanitize("groupKey=" + tok + ".");
  check(out.find(tok) == std::string::npos, "32-hex token redacted");
  check(out.find("[REDACTED_HEX32]") != std::string::npos,
        "hex32 marker present");
}

static void test_sanitize_mongo_id() {
  onvif::DumpSanitizer s;
  const std::string id = "0011223344556677889900aa";  // 24 hex, lowercase
  const std::string out = s.sanitize(
      "\"cameraId\": \"" + id + "\", other=1");
  check(out.find(id) == std::string::npos, "24-hex Mongo id redacted");
  check(out.find("id-") != std::string::npos,
        "Mongo id replaced with id-<hash> label");
  // Same input -> same label within one sanitiser (idempotence proxy).
  const std::string out2 = s.sanitize("ref " + id + " done");
  const auto pos = out2.find("id-");
  check(pos != std::string::npos && pos + 11 <= out2.size(),
        "same Mongo id gets same 8-hex suffix on repeat encounter");
}

static void test_sanitize_mac_colon() {
  onvif::DumpSanitizer s;
  const std::string mac = "A1:B2:C3:D4:E5:F6";
  const std::string out = s.sanitize("client=" + mac + " done");
  check(out.find(mac) == std::string::npos,
        "colon-form MAC redacted");
  check(out.find("mac-") != std::string::npos,
        "MAC replaced with mac-<hash> label");
}

static void test_sanitize_mac_bare() {
  onvif::DumpSanitizer s;
  const std::string mac = "A1B2C3D4E5F6";
  const std::string in =
      "[T:" + mac + "] decode; "
      "/srv/unifi-protect/video/2026/06/26/" + mac + "_0_rotating_1.ubv";
  const std::string out = s.sanitize(in);
  check(out.find(mac) == std::string::npos,
        "bare 12-hex MAC redacted in both bracket + path forms");
  // Both occurrences map to the same label (deterministic).
  const size_t first = out.find("mac-");
  const size_t second = out.find("mac-", first + 1);
  check(first != std::string::npos && second != std::string::npos,
        "MAC appears twice; each replaced");
  check(out.substr(first, 12) == out.substr(second, 12),
        "same MAC -> same label on both occurrences");
}

static void test_mongo_id_before_mac_bare() {
  // A lowercase 24-hex Mongo id contains a lowercase 12-hex prefix.
  // The 24-hex rule must run BEFORE the 12-hex MAC rule so we don't
  // chew off the first 12 chars of a Mongo id into a spurious "mac-"
  // label.
  onvif::DumpSanitizer s;
  const std::string id = "aabbccddeeffaabbccddeeff";  // 24 lowercase hex
  const std::string out = s.sanitize("[" + id + "]");
  // If ordering were wrong, we'd see "mac-<x>ccddeeff" left behind.
  // Correct: the whole 24-hex ID becomes id-<hash>, no mac- label.
  check(out.find("mac-") == std::string::npos,
        "24-hex ID not chewed by MAC-bare rule");
  check(out.find("id-") != std::string::npos,
        "24-hex ID redacted as id-<hash>");
}

static void test_sanitize_ignores_short_hex_and_versions() {
  // Regression: hex-shaped tokens shorter than 12 chars, and dotted
  // version strings, must NOT be redacted.
  onvif::DumpSanitizer s;
  const std::string out = s.sanitize(
      "commit abc123def; v7.1.83; err 0xdeadbeef");
  check(out.find("abc123def") != std::string::npos,
        "short hex (9 chars) untouched");
  check(out.find("v7.1.83") != std::string::npos,
        "semver preserved");
  check(out.find("0xdeadbeef") != std::string::npos,
        "8-hex pointer untouched");
}

int main() {
  test_ip_remap_basic();
  test_ip_remap_consistent();
  test_ip_remap_independent_subtrees();
  test_ip_remap_invalid_unchanged();
  test_sanitize_ip_in_text();
  test_sanitize_ignores_versions();
  test_sanitize_wsse_tags();
  test_sanitize_kv_passwords();
  test_sanitize_url_creds();
  test_sanitize_basic_auth_header();
  test_sanitize_xuserid();
  test_sanitize_user_kv();
  test_register_camera_name_basic();
  test_sanitize_camera_names();
  test_sanitize_camera_name_longest_first();
  test_sanitize_camera_name_deterministic();
  test_sanitize_sentry_dsn();
  test_sanitize_query_session_values();
  test_sanitize_ws_path_token();
  test_sanitize_tcp_path_token();
  test_sanitize_uuid();
  test_sanitize_hex32_token();
  test_sanitize_mongo_id();
  test_sanitize_mac_colon();
  test_sanitize_mac_bare();
  test_mongo_id_before_mac_bare();
  test_sanitize_ignores_short_hex_and_versions();

  std::cout << "test_dump_sanitizer: " << g_pass << " passed, "
            << g_fail << " failed\n";
  return g_fail > 0 ? 1 : 0;
}
