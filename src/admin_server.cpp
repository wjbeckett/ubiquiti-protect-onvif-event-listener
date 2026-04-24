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

#include "admin_server.hpp"

#include <arpa/inet.h>
#include <microhttpd.h>
#include <netinet/in.h>

#if MHD_VERSION < 0x00097100
typedef int MHD_Result;
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

#include "absl/log/log.h"

namespace onvif {

// The admin UI is embedded so the package has no external HTML/JS to manage.
// Styled to match UniFi's dark cards + accent blue.  Kept deliberately small.
static const char kAdminHtml[] = R"HTML(<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>onvif-recorder admin</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{background:#0e1118;color:#e8eaed;font-family:-apple-system,system-ui,sans-serif;
margin:0;padding:24px;max-width:720px}
h1{font-size:20px;color:#8be9fd;margin:0 0 16px 0}
.card{background:#1a1f2b;border:1px solid #2a3140;border-radius:6px;
padding:16px;margin-bottom:12px}
.card h2{font-size:14px;color:#9aa0a6;margin:0 0 8px 0;text-transform:uppercase;
letter-spacing:.04em}
.row{display:flex;align-items:center;gap:8px;margin:6px 0}
.row label{flex:1;color:#c6c9cc}
button,select,input[type=text]{background:#111621;color:#e8eaed;
border:1px solid #3a4255;border-radius:4px;padding:6px 12px;font-size:13px}
button{cursor:pointer;background:#1e6feb;border-color:#1e6feb;color:#fff}
button:hover{background:#3d85ef}
button.danger{background:#b23;border-color:#b23}
button.danger:hover{background:#d44}
.kv{display:grid;grid-template-columns:150px 1fr;gap:6px;font-size:13px}
.kv .k{color:#9aa0a6}
.msg{padding:8px 12px;border-radius:4px;margin-top:8px;font-size:13px;display:none}
.msg.ok{background:#1a3a1a;color:#a0e0a0;display:block}
.msg.err{background:#3a1a1a;color:#e0a0a0;display:block}
</style></head><body>
<h1>ONVIF Recorder</h1>

<div class="card"><h2>Status</h2>
<div class="kv" id="status">Loading…</div></div>

<div class="card"><h2>Release channel</h2>
<div class="row"><label>APT suite used for upgrades</label>
<select id="channel">
<option value="stable">stable</option>
<option value="rc">rc</option>
<option value="early-access">early-access</option>
</select>
<button onclick="setChannel()">Apply</button></div>
<div class="msg" id="channel-msg"></div></div>

<div class="card"><h2>Auto-update</h2>
<div class="row"><label>Install new releases automatically</label>
<select id="autoupdate-enabled">
<option value="true">Enabled</option>
<option value="false">Disabled</option>
</select></div>
<div class="row"><label>Schedule (systemd OnCalendar)</label>
<input type="text" id="autoupdate-schedule" placeholder="daily"></div>
<div class="row"><button onclick="setAutoupdate()">Apply</button>
<button onclick="checkNow()">Check now</button></div>
<div class="msg" id="autoupdate-msg"></div></div>

<div class="card"><h2>Uninstall</h2>
<div class="row"><label>Remove onvif-recorder and all patches</label>
<button class="danger" onclick="uninstall()">Uninstall</button></div>
<div class="msg" id="uninstall-msg"></div></div>

<script>
async function fetchStatus(){
  const r = await fetch('api/status');
  const j = await r.json();
  const rows = [
    ['Version', j.version],
    ['Channel', j.channel],
    ['Auto-update', j.autoupdate_enabled ? 'enabled ('+j.autoupdate_schedule+')' : 'disabled'],
    ['Last check', j.last_check || 'never'],
  ];
  document.getElementById('status').innerHTML =
    rows.map(([k,v]) => `<span class="k">${k}</span><span>${v}</span>`).join('');
  document.getElementById('channel').value = j.channel;
  document.getElementById('autoupdate-enabled').value = String(!!j.autoupdate_enabled);
  document.getElementById('autoupdate-schedule').value = j.autoupdate_schedule || 'daily';
}
function msg(id, text, ok){
  const e = document.getElementById(id);
  e.textContent = text;
  e.className = 'msg ' + (ok ? 'ok' : 'err');
}
async function post(path, body){
  const r = await fetch(path, {method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body||{})});
  return {ok: r.ok, text: await r.text()};
}
async function setChannel(){
  const v = document.getElementById('channel').value;
  const r = await post('api/channel', {channel: v});
  msg('channel-msg', r.text, r.ok);
  if (r.ok) fetchStatus();
}
async function setAutoupdate(){
  const enabled = document.getElementById('autoupdate-enabled').value === 'true';
  const schedule = document.getElementById('autoupdate-schedule').value || 'daily';
  const r = await post('api/autoupdate', {enabled, schedule});
  msg('autoupdate-msg', r.text, r.ok);
  if (r.ok) fetchStatus();
}
async function checkNow(){
  const r = await post('api/check', {});
  msg('autoupdate-msg', r.text, r.ok);
}
async function uninstall(){
  if (!confirm('Uninstall onvif-recorder? This stops the service, removes the package, and rolls back UI/nginx patches.')) return;
  const r = await post('api/uninstall', {});
  msg('uninstall-msg', r.text, r.ok);
}
fetchStatus();
setInterval(fetchStatus, 30000);
</script>
</body></html>
)HTML";

namespace {

// Helper: run a shell command, capture stdout+stderr, return exit code.
// Bounded output (max 16 KiB) to avoid runaway memory if a command misbehaves.
int run_cmd(const std::string& cmd, std::string* output) {
  std::string full = cmd + " 2>&1";
  FILE* pipe = popen(full.c_str(), "r");
  if (!pipe) {
    if (output) *output = "popen failed";
    return -1;
  }
  char buf[1024];
  size_t total = 0;
  while (total < 16384 && std::fgets(buf, sizeof(buf), pipe)) {
    size_t n = std::strlen(buf);
    if (output) output->append(buf, n);
    total += n;
  }
  int rc = pclose(pipe);
  return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

// Read the contents of a file into a string.  Returns empty on failure.
std::string read_file(const std::string& path) {
  std::ifstream f(path);
  if (!f.is_open()) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Write a string atomically to a file: write to .tmp, rename.
bool write_file(const std::string& path, const std::string& content) {
  const std::string tmp = path + ".tmp";
  {
    std::ofstream f(tmp);
    if (!f.is_open()) return false;
    f << content;
    if (!f.good()) return false;
  }
  return std::rename(tmp.c_str(), path.c_str()) == 0;
}

// Trim trailing whitespace/newlines.
std::string trim(std::string s) {
  while (!s.empty() &&
         (s.back() == '\n' || s.back() == '\r' || s.back() == ' '))
    s.pop_back();
  return s;
}

// Very small JSON string extractor: finds `"key":"..."` and returns the value.
// Does not handle escapes beyond \\ and \" — sufficient for our single-field
// bodies from the admin page.
std::string json_string_field(const std::string& body, const std::string& key) {
  const std::string needle = "\"" + key + "\"";
  size_t p = body.find(needle);
  if (p == std::string::npos) return {};
  p = body.find(':', p);
  if (p == std::string::npos) return {};
  p = body.find('"', p);
  if (p == std::string::npos) return {};
  ++p;
  std::string out;
  while (p < body.size() && body[p] != '"') {
    if (body[p] == '\\' && p + 1 < body.size()) {
      out += body[p + 1];
      p += 2;
    } else {
      out += body[p++];
    }
  }
  return out;
}

// Extract a boolean field.  Returns default_val if not found.
bool json_bool_field(const std::string& body,
                     const std::string& key,
                     bool default_val) {
  const std::string needle = "\"" + key + "\"";
  size_t p = body.find(needle);
  if (p == std::string::npos) return default_val;
  p = body.find(':', p);
  if (p == std::string::npos) return default_val;
  while (p + 1 < body.size() &&
         (body[p + 1] == ' ' || body[p + 1] == '\t'))
    ++p;
  if (body.compare(p + 1, 4, "true") == 0) return true;
  if (body.compare(p + 1, 5, "false") == 0) return false;
  return default_val;
}

// Per-connection context for accumulating POST bodies across libmicrohttpd's
// upload-data callbacks.
struct PostCtx {
  std::string body;
};

// Request-scoped state passed to handler via MHD_create_response_from_buffer.
struct Ctx {
  const char* version;
  const char* channel_file;
};

// Build a JSON response body for GET /api/status.
std::string build_status_json(const Ctx& ctx) {
  std::string channel = trim(read_file(ctx.channel_file));
  if (channel.empty()) channel = "stable";

  // Prefer the installed package version (accurate when invoked via the .deb)
  // over the compile-time ONVIF_RECORDER_VERSION constant, which is "dev" for
  // any binary Bazel produced outside a release build.
  std::string version;
  {
    std::string out;
    if (run_cmd("dpkg-query -W -f='${Version}' onvif-recorder 2>/dev/null",
                &out) == 0) {
      version = trim(out);
    }
    if (version.empty()) version = ctx.version;
  }

  // `systemctl is-enabled onvif-recorder-autoupdate.timer` returns
  // "enabled" / "disabled" / "masked" on stdout.  We treat non-enabled as
  // disabled.
  std::string enabled_out;
  run_cmd("systemctl is-enabled onvif-recorder-autoupdate.timer",
          &enabled_out);
  bool enabled = trim(enabled_out) == "enabled";

  // Read the current OnCalendar= from a drop-in override if present.
  std::string schedule = "daily";
  std::string dropin = read_file(
      "/etc/systemd/system/onvif-recorder-autoupdate.timer.d/schedule.conf");
  size_t p = dropin.find("OnCalendar=");
  if (p != std::string::npos) {
    p += std::strlen("OnCalendar=");
    size_t end = dropin.find('\n', p);
    schedule = dropin.substr(p, end - p);
  }

  std::string last_check;
  {
    std::string out;
    run_cmd("systemctl show onvif-recorder-autoupdate.service "
            "-p ExecMainStartTimestamp --value",
            &out);
    last_check = trim(out);
  }

  // Hand-rolled JSON; all fields are ASCII-safe.
  std::string j;
  j += "{\"version\":\"";
  j += version;
  j += "\",\"channel\":\"";
  j += channel;
  j += "\",\"autoupdate_enabled\":";
  j += enabled ? "true" : "false";
  j += ",\"autoupdate_schedule\":\"";
  j += schedule;
  j += "\",\"last_check\":\"";
  j += last_check;
  j += "\"}";
  return j;
}

// Handle POST /api/channel — body {"channel":"stable|rc|early-access"}.
std::pair<int, std::string> handle_channel(const Ctx& ctx,
                                           const std::string& body) {
  std::string channel = json_string_field(body, "channel");
  if (channel != "stable" && channel != "rc" && channel != "early-access") {
    return {400, "invalid channel (stable, rc, early-access)"};
  }
  if (!write_file(ctx.channel_file, channel + "\n")) {
    return {500, std::string("failed to write ") + ctx.channel_file};
  }
  std::string out;
  int rc = run_cmd(
      "/usr/libexec/onvif-recorder/install-apt-source.sh && "
      "apt-get update -o Dir::Etc::sourcelist="
      "/etc/apt/sources.list.d/onvif-recorder.list "
      "-o Dir::Etc::sourceparts=- "
      "-o APT::Get::List-Cleanup=0",
      &out);
  if (rc != 0) return {500, "apt update failed: " + out};
  return {200, "channel set to " + channel};
}

// Handle POST /api/check — fire force-check via autoupdate.service.
std::pair<int, std::string> handle_check() {
  std::string out;
  int rc = run_cmd(
      "systemctl start --no-block onvif-recorder-autoupdate.service",
      &out);
  if (rc != 0) return {500, "systemctl start failed: " + out};
  return {200, "update check started"};
}

// Handle POST /api/autoupdate — body {enabled:bool, schedule:"..."}.
std::pair<int, std::string> handle_autoupdate(const std::string& body) {
  bool enabled = json_bool_field(body, "enabled", true);
  std::string schedule = json_string_field(body, "schedule");
  if (schedule.empty()) schedule = "daily";

  // Reject any character that isn't safe in an OnCalendar= value to avoid
  // shell / ini injection.  OnCalendar syntax is quite liberal so we allow
  // letters, digits, colon, dash, comma, slash, dot, asterisk, space.
  for (char c : schedule) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == ':' || c == '-' || c == ',' || c == '/' ||
              c == '.' || c == '*' || c == ' ';
    if (!ok) return {400, "invalid character in schedule"};
  }

  // Write/remove the drop-in file that sets OnCalendar=.
  const char kDropinDir[] =
      "/etc/systemd/system/onvif-recorder-autoupdate.timer.d";
  const char kDropinFile[] =
      "/etc/systemd/system/onvif-recorder-autoupdate.timer.d/schedule.conf";
  std::string mkdir_out;
  (void)run_cmd(std::string("mkdir -p ") + kDropinDir, &mkdir_out);
  std::string conf =
      "[Timer]\nOnCalendar=\nOnCalendar=" + schedule + "\n";
  if (!write_file(kDropinFile, conf)) {
    return {500, "failed to write timer drop-in"};
  }

  std::string out;
  if (enabled) {
    (void)run_cmd("systemctl daemon-reload", &out);
    int rc = run_cmd(
        "systemctl enable --now onvif-recorder-autoupdate.timer", &out);
    if (rc != 0) return {500, "systemctl enable failed: " + out};
    return {200, "auto-update enabled (" + schedule + ")"};
  }
  (void)run_cmd("systemctl daemon-reload", &out);
  int rc = run_cmd(
      "systemctl disable --now onvif-recorder-autoupdate.timer", &out);
  if (rc != 0) return {500, "systemctl disable failed: " + out};
  return {200, "auto-update disabled"};
}

// Handle POST /api/uninstall — fire apt-get remove in the background.
std::pair<int, std::string> handle_uninstall() {
  // Detach: the running process is about to be stopped by apt-get.
  std::string out;
  int rc = run_cmd(
      "systemd-run --unit=onvif-recorder-uninstall "
      "--no-block apt-get remove -y onvif-recorder",
      &out);
  if (rc != 0) return {500, "systemd-run failed: " + out};
  return {200, "uninstall scheduled"};
}

MHD_Result handler(
    void* cls,
    struct MHD_Connection* connection,
    const char* url,
    const char* method,
    const char* /*version*/,
    const char* upload_data,
    size_t* upload_data_size,
    void** con_cls) {
  auto* ctx = static_cast<Ctx*>(cls);
  const bool is_post = std::strcmp(method, "POST") == 0;
  // Treat HEAD identically to GET for dispatch; libmicrohttpd strips the
  // body automatically on HEAD responses.  Without this, HEAD requests
  // (used by some health-check probes and curl -I) fall through to 404.
  const bool is_get  = std::strcmp(method, "GET") == 0 ||
                       std::strcmp(method, "HEAD") == 0;

  // libmicrohttpd calls us at least twice for POST: once to begin, then for
  // each chunk of upload_data.  Accumulate into a PostCtx.
  if (is_post) {
    if (*con_cls == nullptr) {
      *con_cls = new PostCtx();
      return MHD_YES;
    }
    auto* pc = static_cast<PostCtx*>(*con_cls);
    if (*upload_data_size > 0) {
      pc->body.append(upload_data, *upload_data_size);
      *upload_data_size = 0;
      return MHD_YES;
    }
  }

  // Dispatch.
  int status = 200;
  std::string body;
  std::string content_type = "text/plain; charset=utf-8";

  if (is_get &&
      (std::strcmp(url, "/admin/") == 0 || std::strcmp(url, "/admin") == 0 ||
       std::strcmp(url, "/") == 0)) {
    body = kAdminHtml;
    content_type = "text/html; charset=utf-8";
  } else if (is_get &&
             std::strcmp(url, "/api/status") == 0) {
    body = build_status_json(*ctx);
    content_type = "application/json";
  } else if (is_post) {
    auto* pc = static_cast<PostCtx*>(*con_cls);
    const std::string& pb = pc->body;
    std::pair<int, std::string> r{404, "not found"};
    if (std::strcmp(url, "/api/channel") == 0)
      r = handle_channel(*ctx, pb);
    else if (std::strcmp(url, "/api/check") == 0)
      r = handle_check();
    else if (std::strcmp(url, "/api/autoupdate") == 0)
      r = handle_autoupdate(pb);
    else if (std::strcmp(url, "/api/uninstall") == 0)
      r = handle_uninstall();
    status = r.first;
    body = std::move(r.second);
    delete pc;
    *con_cls = nullptr;
  } else {
    status = 404;
    body = "not found";
  }

  struct MHD_Response* resp = MHD_create_response_from_buffer(
      body.size(),
      const_cast<char*>(body.data()),
      MHD_RESPMEM_MUST_COPY);
  MHD_add_response_header(resp, "Content-Type", content_type.c_str());
  MHD_add_response_header(resp, "Cache-Control", "no-store");
  MHD_Result ret = MHD_queue_response(connection, status, resp);
  MHD_destroy_response(resp);
  return ret;
}

void request_completed(void* /*cls*/,
                       struct MHD_Connection* /*conn*/,
                       void** con_cls,
                       enum MHD_RequestTerminationCode /*toe*/) {
  if (*con_cls) {
    delete static_cast<PostCtx*>(*con_cls);
    *con_cls = nullptr;
  }
}

}  // namespace

bool AdminServer::start(const std::string& version,
                        const std::string& channel_file,
                        uint16_t port) {
  version_ = version;
  channel_file_ = channel_file;

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  // Leaked Ctx: one per server instance; lives for the program lifetime.
  auto* ctx = new Ctx{version_.c_str(), channel_file_.c_str()};

  daemon_ = MHD_start_daemon(
      MHD_USE_INTERNAL_POLLING_THREAD,
      port,
      nullptr, nullptr,
      &handler, ctx,
      MHD_OPTION_NOTIFY_COMPLETED, &request_completed, nullptr,
      MHD_OPTION_SOCK_ADDR,
      reinterpret_cast<struct sockaddr*>(&addr),
      MHD_OPTION_END);
  if (!daemon_) return false;

  // Record the bound port so callers that passed port=0 can discover it.
  const union MHD_DaemonInfo* info =
      MHD_get_daemon_info(daemon_, MHD_DAEMON_INFO_BIND_PORT);
  port_ = info ? info->port : port;
  return true;
}

void AdminServer::stop() {
  if (daemon_) {
    MHD_stop_daemon(daemon_);
    daemon_ = nullptr;
  }
}

AdminServer::~AdminServer() {
  stop();
}

}  // namespace onvif
