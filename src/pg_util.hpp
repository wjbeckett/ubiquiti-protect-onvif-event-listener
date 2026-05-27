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

#include <libpq-fe.h>

#include <cstdint>

namespace onvif {
namespace pg {

// Default per-query wall-clock timeout (milliseconds).
//
// 60s is high enough that legitimate slow INSERTs under load (e.g. during
// the 7-day startup backfill, when motion_poller bursts ~50 events through
// in a few seconds and Protect itself is also writing to the same tables)
// don't trip a false timeout, but short enough that a silently-dropped
// TCP connection to the Protect DB stops a thread for at most a minute
// rather than indefinitely (issue #34: motion_poller hung for hours when
// libpq's ppoll(timeout=NULL) waited on a half-closed socket).
//
// Long-running maintenance queries (e.g. the 30-day coalesce_history
// scan) explicitly pass a longer timeout.
constexpr int kDefaultTimeoutMs = 60'000;

// Drop-in replacement for PQexecParams() that returns nullptr if the
// query does not complete within @p timeout_ms wall-clock milliseconds.
//
// Implementation: PQsendQueryParams() + a poll(socket) loop that
// respects the deadline.  On timeout, sends PQcancel and drains any
// straggler results so the connection is reusable for the next call.
//
// Caller still owns the returned PGresult (PQclear it) and must still
// check PQresultStatus() for SQL-level errors.
//
// timeout_ms <= 0 falls back to kDefaultTimeoutMs.
//
// Logs a single ERROR line on timeout/cancel/connection drop with the
// SQL text truncated to 200 chars so journal forensics can identify
// the responsible query without needing per-call-site logging.
PGresult* ExecParamsWithTimeout(PGconn* conn,
                                 int timeout_ms,
                                 const char* sql,
                                 int n_params,
                                 const Oid* param_types,
                                 const char* const* param_values,
                                 const int* param_lengths,
                                 const int* param_formats,
                                 int result_format);

// No-params variant matching PQexec().  Same timeout semantics.
PGresult* ExecWithTimeout(PGconn* conn, int timeout_ms, const char* sql);

// Variant that returns a single binary result row of arbitrary size,
// matching PQexecParams(..., result_format=1).  Exists as a convenience
// only -- ExecParamsWithTimeout with result_format=1 produces the same
// PGresult.

}  // namespace pg
}  // namespace onvif
