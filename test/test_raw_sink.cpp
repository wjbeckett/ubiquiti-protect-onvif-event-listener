// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "onvif_listener.hpp"

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

// Count newline-terminated lines in a JSONL string.
static size_t count_lines(const std::string& s) {
  size_t n = 0;
  for (char c : s) if (c == '\n') ++n;
  return n;
}

// Each call into RawSink::record() should emit exactly one JSONL line
// in the snapshot.
static void test_record_round_trips_into_snapshot() {
  auto& sink = onvif::RawSink::instance();
  // Push a handful of records — well under the entry cap.
  for (int i = 0; i < 100; ++i) {
    sink.record("0.0.0.0", "u", "a", "req", 200, "resp");
  }

  const std::string before = sink.snapshot();
  const size_t lines_before = count_lines(before);

  sink.record("192.168.1.108", "http://x/onvif/event_service",
              "GetServices", "<reqA/>", 200, "<respA/>");
  sink.record("192.168.1.109", "http://y/onvif/event_service",
              "Subscribe", "<reqB/>", 401, "<respB/>");

  const std::string after = sink.snapshot();
  const size_t lines_after = count_lines(after);

  // Two new records must be in the snapshot, but the ring is bounded so
  // older entries fall off — line delta is therefore <= 2 (== 0 when the
  // ring was already full and we evicted in lock-step).
  check(lines_after >= lines_before - 2,
        "snapshot did not collapse unexpectedly");

  // The new payloads themselves must be in the snapshot regardless of
  // eviction.
  check(after.find("\"camera_ip\":\"192.168.1.108\"")
          != std::string::npos,
        "first record payload present in snapshot");
  check(after.find("\"camera_ip\":\"192.168.1.109\"")
          != std::string::npos,
        "second record payload present in snapshot");
  check(after.find("\"response_status\":401") != std::string::npos,
        "response status preserved in snapshot");
}

// The ring must hold at least 50000 entries (proves kMaxEntries was
// actually bumped to 50k and not still at the old 1k value) and never
// exceed it.  Test pushes 60k tiny records (well under the 64 MiB
// byte cap) so the line cap is what's being exercised.
static void test_ring_caps_entry_count() {
  auto& sink = onvif::RawSink::instance();
  for (int i = 0; i < 60000; ++i) {
    sink.record("0.0.0.0", "u", "a", "q", 200, "r");
  }
  const size_t lines = count_lines(sink.snapshot());
  check(lines >= 50000, "ring keeps last 50000 entries");
  check(lines <= 50000, "ring entry-count cap enforced");
}

// Pushing realistic SOAP-shaped payloads must produce a smaller in-RAM
// ring than the same data uncompressed.  This verifies the zstd path is
// actually compressing rather than passing through raw.  We push enough
// SOAP records to fully evict any prior test state (>50k entry cap) so
// the measured ratio reflects only the SOAP payload.
static void test_ring_compresses_soap_xml() {
  auto& sink = onvif::RawSink::instance();
  const std::string soap_request =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\""
      " xmlns:wsa=\"http://www.w3.org/2005/08/addressing\""
      " xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
      "<SOAP-ENV:Header><wsa:Action>"
      "http://www.onvif.org/ver10/events/wsdl/PullPointSubscription/PullMessages"
      "</wsa:Action></SOAP-ENV:Header><SOAP-ENV:Body><tt:PullMessages>"
      "<tt:Timeout>PT60S</tt:Timeout><tt:MessageLimit>1024</tt:MessageLimit>"
      "</tt:PullMessages></SOAP-ENV:Body></SOAP-ENV:Envelope>";
  const std::string soap_response =
      "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://www.w3.org/2003/05/soap-envelope\""
      " xmlns:tt=\"http://www.onvif.org/ver10/schema\">"
      "<SOAP-ENV:Body><tt:NotificationMessage>"
      "<tt:Topic>tns1:RuleEngine/CellMotionDetector/Motion</tt:Topic>"
      "<tt:Message UtcTime=\"2026-04-26T10:00:00Z\" PropertyOperation=\"Initialized\">"
      "<tt:Source><tt:SimpleItem Name=\"VideoSourceConfigurationToken\""
      " Value=\"VideoSource_1\"/></tt:Source>"
      "<tt:Data><tt:SimpleItem Name=\"IsMotion\" Value=\"true\"/></tt:Data>"
      "</tt:Message></tt:NotificationMessage></SOAP-ENV:Body></SOAP-ENV:Envelope>";

  // Push more than kMaxEntries (50000) to fully evict any prior
  // tiny-record state from earlier tests in this binary.
  for (int i = 0; i < 50100; ++i) {
    sink.record("192.168.1.42",
                "http://192.168.1.42/onvif/event_service",
                "PullMessages",
                soap_request, 200, soap_response);
  }
  const size_t snap_bytes = sink.snapshot().size();
  const size_t ring_bytes = sink.compressed_bytes();

  // Compressed ring must be strictly smaller than the decompressed
  // snapshot of the same data.  For SOAP XML, zstd-3 typically yields
  // > 4x; we assert > 2x to leave headroom for any minor variance.
  check(ring_bytes * 2 < snap_bytes,
        "compressed ring at least 2x smaller than decompressed snapshot");
  // Sanity: snapshot must contain a recognisable XML fragment.
  check(sink.snapshot().find("CellMotionDetector") != std::string::npos,
        "snapshot decompresses readable XML");
}

// enable_disk("") clears any previously-set disk tee but leaves the ring
// active; enable_disk(path) tees subsequent records to the file.
static void test_disk_tee_optional_and_idempotent() {
  auto& sink = onvif::RawSink::instance();
  // Start with disk disabled.
  sink.enable_disk("");

  // Enable to a temp file.
  char path[] = "/tmp/raw_sink_test_XXXXXX";
  int fd = mkstemp(path);
  check(fd >= 0, "mkstemp ok");
  close(fd);
  sink.enable_disk(path);

  sink.record("10.0.0.1", "/u", "PullMessages", "rq", 200, "rs");

  // The ring snapshot should still contain the record.
  check(sink.snapshot().find("\"camera_ip\":\"10.0.0.1\"")
          != std::string::npos,
        "ring still receives records when disk tee is on");

  // The disk file should contain at least one line ending in \n with our
  // payload.
  std::ifstream f(path);
  std::stringstream ss;
  ss << f.rdbuf();
  const std::string disk = ss.str();
  check(disk.find("\"camera_ip\":\"10.0.0.1\"") != std::string::npos,
        "disk tee wrote the record");
  check(!disk.empty() && disk.back() == '\n',
        "disk tee writes JSONL with trailing newline");

  // Disabling the disk tee should stop further writes but not affect the
  // ring.
  sink.enable_disk("");
  sink.record("10.0.0.2", "/u", "PullMessages", "rq", 200, "rs");

  std::ifstream f2(path);
  std::stringstream ss2;
  ss2 << f2.rdbuf();
  const std::string disk2 = ss2.str();
  check(disk2.find("\"camera_ip\":\"10.0.0.2\"") == std::string::npos,
        "no further writes after disk tee disabled");
  check(sink.snapshot().find("\"camera_ip\":\"10.0.0.2\"")
          != std::string::npos,
        "ring still records after disk tee disabled");

  std::remove(path);
}

int main() {
  test_record_round_trips_into_snapshot();
  test_ring_caps_entry_count();
  test_disk_tee_optional_and_idempotent();
  test_ring_compresses_soap_xml();
  std::cout << "test_raw_sink: " << g_pass << " passed, "
            << g_fail << " failed\n";
  return g_fail > 0 ? 1 : 0;
}
