// Copyright 2026 Daniel W
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <string>

#include "absl/synchronization/mutex.h"

namespace onvif {

// Process-global, always-on contention profiler.  Wraps absl's
// RegisterMutexProfiler hook (called on every absl::Mutex unlock with
// the wait_cycles for that lock) and aggregates per-mutex-name stats:
//
//   - acquisitions:        number of times the lock was taken
//   - contended_acquires:  number of those that waited (wait_cycles > 0)
//   - total_wait_ns:       sum of wait time across contended_acquires
//   - max_wait_ns:         worst wait observed
//
// Requires each tracked mutex to be registered by name via
// register_mutex(addr, name) before any traffic.  Unregistered mutexes
// are still aggregated under the synthetic name "(unknown)".
//
// snapshot() renders the table as a fixed-width text dump for
// /api/contentionz.  Cost in production: one atomic add per unlock,
// plus one std::map lookup; under our 7-mutex / few-Hz workload this
// is unmeasurable.
class ContentionProfiler {
 public:
  static ContentionProfiler& instance();

  // Tag @p mu with @p name so subsequent stats lines identify it.
  // Idempotent.  Calling with a different name overwrites the prior
  // tag.  Must be called before the mutex sees traffic for the stats
  // to be useful.
  void register_mutex(const absl::Mutex* mu, std::string name);

  // Install absl's RegisterMutexProfiler hook.  Call once at program
  // start, before any other thread might unlock an absl::Mutex.
  static void install();

  // Render current stats as a fixed-width text table.  Used by
  // /api/contentionz.
  std::string snapshot() const;

 private:
  ContentionProfiler() = default;

  struct Entry {
    std::string name;
    std::atomic<uint64_t> acquisitions{0};
    std::atomic<uint64_t> contended{0};
    std::atomic<uint64_t> total_wait_ns{0};
    std::atomic<uint64_t> max_wait_ns{0};
  };

  // Called from absl's RegisterMutexTracer callback for "slow lock"
  // events (acquire that had to wait).  obj is the absl::Mutex
  // pointer; wait_cycles converts to ns via the cached
  // ns_per_cycle_ rate.
  void record_slow_lock(const absl::Mutex* mu, int64_t wait_cycles);
  static void on_trace(const char* msg, const void* obj,
                       int64_t wait_cycles);

  // Address-keyed; one Entry per registered mutex plus an "(unknown)"
  // bucket for unregistered ones.  Lookups are protected by mu_.
  mutable absl::Mutex mu_;
  std::map<const absl::Mutex*, Entry*> entries_;
  Entry unknown_;

  // The absl callback is a global free function with no per-instance
  // context, so we keep a static pointer back to the singleton.
  static ContentionProfiler* g_instance_;

  // For absl::base_internal::CycleClock-style conversion.  Cached at
  // install() time.
  double ns_per_cycle_{1.0};
};

}  // namespace onvif
