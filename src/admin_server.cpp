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
#include <curl/curl.h>
#include <gperftools/malloc_extension.h>
#include <microhttpd.h>
#include <netinet/in.h>

#if MHD_VERSION < 0x00097100
typedef int MHD_Result;
#endif

#include <signal.h>
#include <unistd.h>

#include <chrono>  // NOLINT(build/c++11)
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/commandlineflag.h"
#include "absl/flags/reflection.h"
#include "absl/log/log.h"
#include "absl/status/status.h"

#include "contention_profiler.hpp"
#include "dump_sanitizer.hpp"
#include "onvif_listener.hpp"
#include "runtime_config.hpp"

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
.cfg-row{display:grid;grid-template-columns:240px 1fr;gap:8px;align-items:start;margin:6px 0}
.cfg-row label{color:#c6c9cc;font-size:13px}
.cfg-row .desc{color:#7a8190;font-size:12px;margin-top:2px}
.cfg-row .input input,.cfg-row .input select{width:100%;box-sizing:border-box}
.cfg-row .placeholder{color:#5a6172;font-size:11px;margin-top:2px}
.cfg-section{font-size:13px;color:#9aa0a6;text-transform:uppercase;letter-spacing:.04em;
margin:12px 0 4px 0;border-top:1px solid #2a3140;padding-top:12px}
.cfg-section:first-child{border-top:0;padding-top:0;margin-top:0}
.fp-list{max-height:240px;overflow-y:auto;border:1px solid #2a3140;border-radius:4px;
padding:6px}
.fp-row{display:flex;align-items:center;gap:8px;padding:2px 0;font-size:13px}
.spinner{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(14,17,24,0.9);
display:none;align-items:center;justify-content:center;flex-direction:column;gap:12px;
z-index:99}
.spinner.on{display:flex}
.spinner-circle{width:36px;height:36px;border:3px solid #3a4255;border-top-color:#1e6feb;
border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.pill.green{background:#1a3a1a;color:#a0e0a0}
.pill.amber{background:#3a2a1a;color:#e0c290}
.pill.red{background:#3a1a1a;color:#e0a0a0}
.pill.grey{background:#2a3140;color:#9aa0a6}
</style></head><body>
<h1>ONVIF Recorder</h1>

<div class="card"><h2>Status</h2>
<div class="kv" id="status">Loading…</div></div>

<div class="card"><h2>Camera health</h2>
<table id="camhealth-table" style="width:100%;border-collapse:collapse;font-size:13px">
<thead><tr style="color:#9aa0a6;text-align:left">
<th style="padding:4px 6px">Name</th>
<th style="padding:4px 6px">Host</th>
<th style="padding:4px 6px">Role</th>
<th style="padding:4px 6px">Last event</th>
<th style="padding:4px 6px">1h</th>
<th style="padding:4px 6px"></th></tr></thead>
<tbody id="camhealth-body"><tr><td colspan="6">Loading…</td></tr></tbody></table></div>

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
<button onclick="checkNow()">Check now</button>
<button onclick="refreshApt()">Refresh package list</button></div>
<div class="msg" id="autoupdate-msg"></div></div>

<div class="card"><h2>First-party cameras</h2>
<p class="desc" style="font-size:12px;color:#9aa0a6;margin:0 0 8px 0">
Tick cameras to enable smart-detect on them via NanoDet-M motion polling.
Saved to the configuration below as <code>first_party_cameras</code>.</p>
<div class="fp-list" id="fp-list">Loading…</div></div>

<div class="card"><h2>Configuration</h2>
<p class="desc" style="font-size:12px;color:#9aa0a6;margin:0 0 8px 0">
Empty fields fall back to flag defaults / unit-file values.  Saving
restarts the service so changes take effect immediately.</p>
<div id="config-form">Loading…</div>
<div class="row"><button onclick="saveConfig()">Save &amp; restart</button></div>
<div class="msg" id="config-msg"></div></div>

<div class="card"><h2>Recent events</h2>
<p class="desc" style="font-size:12px;color:#9aa0a6;margin:0 0 8px 0">
Last 30 events with their snapshot thumbnails.  Thumbnails written
to Protect's <code>thumbnails</code> table are read directly; MSR-stored
snapshots are proxied through Protect's local API.</p>
<div id="recent-events-list" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:8px">Loading…</div></div>

<div class="card"><h2>Diagnostics</h2>
<p class="desc" style="font-size:12px;color:#9aa0a6;margin:0 0 8px 0">
Download a tar.gz of recent journal output, current config, camera-health
snapshot, and version info.  Attach this to a GitHub issue when reporting
problems.</p>
<div class="row"><button onclick="downloadDump()">Download diagnostic dump</button></div>
<div class="msg" id="dump-msg"></div></div>

<div class="card"><h2>Uninstall</h2>
<div class="row"><label>Remove onvif-recorder and all patches</label>
<button class="danger" onclick="uninstall()">Uninstall</button></div>
<div class="msg" id="uninstall-msg"></div></div>

<div class="spinner" id="spinner">
<div class="spinner-circle"></div>
<div id="spinner-text">Restarting service…</div></div>

<script>
// UniFi OS's nginx proxy gates non-GET methods through auth_request, which
// requires the X-Csrf-Token header to match the token nginx attaches to
// every proxied response.  Capture it from each response and echo it on
// subsequent POSTs.  A GET response refreshes csrfToken; if a POST 403s
// (token rotated), retry once after a fresh GET.
let csrfToken = '';
function captureCsrf(r){
  const t = r.headers.get('X-Csrf-Token');
  if (t) csrfToken = t;
  return r;
}
async function fetchStatus(){
  const r = captureCsrf(await fetch('api/status'));
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
async function postOnce(path, body){
  return captureCsrf(await fetch(path, {method:'POST',
    headers:{'Content-Type':'application/json',
             'X-Csrf-Token': csrfToken},
    body: JSON.stringify(body||{})}));
}
async function post(path, body){
  let r = await postOnce(path, body);
  // 403 commonly means the cached CSRF token rotated -- refresh and retry.
  if (r.status === 403) {
    captureCsrf(await fetch('api/status'));
    r = await postOnce(path, body);
  }
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
async function refreshApt(){
  msg('autoupdate-msg', 'Refreshing apt package list…', true);
  const r = await post('api/refresh_apt', {});
  msg('autoupdate-msg', r.text, r.ok);
}
async function downloadDump(){
  msg('dump-msg', 'Building diagnostic archive…', true);
  try {
    const r = await fetch('api/diagnostic_dump');
    if (!r.ok) {
      msg('dump-msg', 'Failed: ' + (await r.text()), false);
      return;
    }
    const blob = await r.blob();
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'onvif-recorder-dump-' + ts + '.tar.gz';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    msg('dump-msg', 'Downloaded.', true);
  } catch (e) {
    msg('dump-msg', 'Failed: ' + e, false);
  }
}
async function uninstall(){
  if (!confirm('Uninstall onvif-recorder? This stops the service, removes the package, and rolls back UI/nginx patches.')) return;
  const r = await post('api/uninstall', {});
  msg('uninstall-msg', r.text, r.ok);
}

// --- Configuration form (driven by /api/config schema) -----------------

let configEntries = [];        // schema entries (one per editable flag)
let firstPartyCameras = [];    // {id, name, mac}
let firstPartyChecked = new Set();  // ticked IDs

function renderConfigForm(entries){
  const root = document.getElementById('config-form');
  let lastGroup = '';
  let html = '';
  for (const e of entries){
    if (e.name === 'first_party_cameras') continue;  // rendered separately
    if (e.group !== lastGroup){
      html += `<div class="cfg-section">${e.group}</div>`;
      lastGroup = e.group;
    }
    let inputHtml;
    if (e.type === 'bool'){
      inputHtml = `<select id="cfg-${e.name}">`
        + `<option value="">(default: ${e.flag_default})</option>`
        + `<option value="true">true</option>`
        + `<option value="false">false</option></select>`;
    } else {
      const ph = `(default: ${e.flag_default || '""'})`;
      inputHtml = `<input type="text" id="cfg-${e.name}" placeholder="${ph}">`;
    }
    html += `<div class="cfg-row"><label>${e.name}<div class="desc">${e.description}</div></label>`
         +  `<div class="input">${inputHtml}</div></div>`;
  }
  root.innerHTML = html;
  // Apply override values.
  for (const e of entries){
    const el = document.getElementById('cfg-' + e.name);
    if (el && e.override) el.value = e.override;
  }
}

function renderFirstPartyList(cams, checked){
  const root = document.getElementById('fp-list');
  if (!cams.length){
    root.innerHTML = `<div style="color:#7a8190">No first-party cameras adopted in Protect.</div>`;
    return;
  }
  root.innerHTML = cams.map(c => {
    const isChecked = checked.has(c.id) ? 'checked' : '';
    return `<div class="fp-row"><input type="checkbox" id="fp-${c.id}" ${isChecked}>`
        +  `<label for="fp-${c.id}">${c.name || '(unnamed)'} `
        +  `<span style="color:#7a8190">[${c.id}]</span></label></div>`;
  }).join('');
}

async function loadConfig(){
  const r = captureCsrf(await fetch('api/config'));
  const j = await r.json();
  configEntries = j.entries || [];
  // first_party_cameras override is a CSV string; expand into the Set.
  firstPartyChecked = new Set();
  const fp = configEntries.find(e => e.name === 'first_party_cameras');
  if (fp && fp.override){
    fp.override.split(',').map(s => s.trim()).filter(Boolean)
      .forEach(id => firstPartyChecked.add(id));
  }
  renderConfigForm(configEntries);
  renderFirstPartyList(firstPartyCameras, firstPartyChecked);
}

async function loadFirstPartyCameras(){
  const r = captureCsrf(await fetch('api/first_party_cameras'));
  const j = await r.json();
  firstPartyCameras = j.cameras || [];
  renderFirstPartyList(firstPartyCameras, firstPartyChecked);
}

async function saveConfig(){
  const values = {};
  for (const e of configEntries){
    if (e.name === 'first_party_cameras') continue;
    const el = document.getElementById('cfg-' + e.name);
    if (el) values[e.name] = el.value || '';
  }
  // Collect ticked first-party cameras into a CSV string.
  const ticked = firstPartyCameras
    .filter(c => document.getElementById('fp-' + c.id)?.checked)
    .map(c => c.id);
  values.first_party_cameras = ticked.join(',');

  const sp = document.getElementById('spinner');
  document.getElementById('spinner-text').textContent = 'Saving config and restarting service…';
  sp.classList.add('on');
  try {
    const r = await post('api/config', values);
    if (!r.ok) {
      msg('config-msg', r.text, false);
      sp.classList.remove('on');
      return;
    }
    // Service is exiting; poll /api/status until it answers again.
    await waitForRestart();
    await loadConfig();
    await fetchStatus();
    msg('config-msg', 'Saved.', true);
  } finally {
    sp.classList.remove('on');
  }
}

async function waitForRestart(){
  const deadline = Date.now() + 30000;  // 30s
  // Brief delay so the old process has time to die before we start polling.
  await new Promise(r => setTimeout(r, 1500));
  while (Date.now() < deadline){
    try {
      const r = await fetch('api/status', {cache: 'no-store'});
      if (r.ok){ captureCsrf(r); return; }
    } catch (_) { /* connection refused while service is down */ }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error('service did not come back within 30s');
}

// --- Camera health card ---
function fmtAge(ms){
  if (!ms || ms <= 0) return 'never';
  const s = Math.max(0, Math.floor(ms / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.floor(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.floor(m / 60);
  if (h < 48) return h + 'h ago';
  return Math.floor(h / 24) + 'd ago';
}
function pillFor(ageMs){
  if (ageMs == null) return '<span class="pill grey">unknown</span>';
  const m = ageMs / 60000;
  if (m < 60)   return '<span class="pill green">healthy</span>';
  if (m < 360)  return '<span class="pill amber">stale</span>';
  return '<span class="pill red">silent</span>';
}
async function loadCameraHealth(){
  try {
    const r = captureCsrf(await fetch('api/camera_health'));
    const j = await r.json();
    const body = document.getElementById('camhealth-body');
    if (!j.cameras || !j.cameras.length){
      body.innerHTML = '<tr><td colspan="6" style="color:#7a8190">No adopted cameras.</td></tr>';
      return;
    }
    const now = j.now_ms || Date.now();
    body.innerHTML = j.cameras.map(c => {
      const age = c.last_event_ms ? (now - c.last_event_ms) : null;
      return `<tr>
        <td style="padding:4px 6px">${c.name || '(unnamed)'}</td>
        <td style="padding:4px 6px;color:#9aa0a6">${c.host || '-'}</td>
        <td style="padding:4px 6px">${c.is_third_party ? 'third-party' : 'first-party'}</td>
        <td style="padding:4px 6px">${fmtAge(age)}</td>
        <td style="padding:4px 6px">${c.events_1h}</td>
        <td style="padding:4px 6px">${pillFor(age)}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    document.getElementById('camhealth-body').innerHTML =
      '<tr><td colspan="6" style="color:#e0a0a0">Failed to load camera health.</td></tr>';
  }
}

// --- Recent events panel ---
function fmtClock(ms){
  if (!ms) return '';
  const d = new Date(ms);
  const pad = n => String(n).padStart(2, '0');
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}
function shortDate(ms){
  const d = new Date(ms);
  const m = d.getMonth() + 1, day = d.getDate();
  return m + '/' + day;
}
async function loadRecentEvents(){
  try {
    const r = captureCsrf(await fetch('api/recent_events'));
    const j = await r.json();
    const root = document.getElementById('recent-events-list');
    if (!j.events || !j.events.length){
      root.innerHTML = '<div style="color:#7a8190">No recent events.</div>';
      return;
    }
    root.innerHTML = j.events.map(ev => {
      const thumb = ev.thumbnail_id
        ? '<img src="api/thumbnail?id=' + encodeURIComponent(ev.thumbnail_id)
            + '" style="width:100%;height:90px;object-fit:cover;border-radius:4px;background:#0e1118" '
            + 'onerror="this.replaceWith(Object.assign(document.createElement(\'div\'),'
            + '{style:\'height:90px;display:flex;align-items:center;justify-content:center;'
            + 'background:#0e1118;border:1px dashed #2a3140;border-radius:4px;color:#5a6172;font-size:11px\','
            + 'textContent:\'no thumb\'}))" loading="lazy">'
        : '<div style="height:90px;display:flex;align-items:center;justify-content:center;'
            + 'background:#0e1118;border:1px dashed #2a3140;border-radius:4px;color:#5a6172;font-size:11px">'
            + 'no thumb</div>';
      const sdt = (ev.sdt && ev.sdt.length)
        ? ev.sdt.join(',')
        : ev.type;
      return `<div style="font-size:11px;color:#c6c9cc">
        ${thumb}
        <div style="margin-top:4px"><span style="color:#8be9fd">${sdt}</span></div>
        <div style="color:#9aa0a6">${ev.camera_name || '-'}</div>
        <div style="color:#7a8190">${shortDate(ev.start_ms)} ${fmtClock(ev.start_ms)}</div>
      </div>`;
    }).join('');
  } catch (e) {
    document.getElementById('recent-events-list').innerHTML =
      '<div style="color:#e0a0a0">Failed to load events.</div>';
  }
}

fetchStatus();
loadFirstPartyCameras();
loadConfig();
loadCameraHealth();
loadRecentEvents();
setInterval(fetchStatus, 30000);
setInterval(loadCameraHealth, 30000);
setInterval(loadRecentEvents, 30000);
</script>
</body></html>
)HTML";

namespace {

// Helper: run a shell command, capture stdout+stderr, return exit code.
// Output is bounded by @p max_bytes to avoid runaway memory if a command
// misbehaves.  The default is 16 KiB which suits status-style probes
// (`systemctl is-enabled`, `dpkg-query -W`, …); the diagnostic dump
// passes a much larger cap because the journal is the whole point of
// the dump.
int run_cmd(const std::string& cmd, std::string* output,
            size_t max_bytes = 16384) {
  std::string full = cmd + " 2>&1";
  FILE* pipe = popen(full.c_str(), "r");
  if (!pipe) {
    if (output) *output = "popen failed";
    return -1;
  }
  char buf[4096];
  size_t total = 0;
  while (total < max_bytes && std::fgets(buf, sizeof(buf), pipe)) {
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

// GET <protect_url>/api/thumbnails/<id> with X-UserId auth.  Returns the
// JPEG bytes on 200, or an empty string on any error / non-200.  Used to
// proxy MSR-stored thumbnails (whose IDs are length != 24 and live as
// native UBV files served by the Protect msp media server) into the
// admin UI's <img src="api/thumbnail?id=..."> path.
std::string fetch_protect_thumbnail(const std::string& protect_url,
                                     const std::string& user_id,
                                     const std::string& thumb_id) {
  if (protect_url.empty() || user_id.empty()) return {};
  std::string url = protect_url + "/api/thumbnails/" + thumb_id;
  std::string buf;
  CURL* curl = curl_easy_init();
  if (!curl) return {};
  struct curl_slist* hdrs = nullptr;
  std::string user_hdr = "X-UserId: " + user_id;
  hdrs = curl_slist_append(hdrs, user_hdr.c_str());
  hdrs = curl_slist_append(hdrs, "X-Source: unifi-os");
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);  // NOLINT(runtime/int)
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);  // NOLINT(runtime/int)
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
      +[](char* p, size_t s, size_t n, void* ud) -> size_t {
        static_cast<std::string*>(ud)->append(p, s * n);
        return s * n;
      });
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
  CURLcode rc = curl_easy_perform(curl);
  long code = 0;  // NOLINT(runtime/int)
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);
  if (rc != CURLE_OK || code != 200) return {};
  return buf;
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
  const char* config_path;
  const unifi::DbConfig* db;  // optional; may have empty conn_string
  const char* protect_url;        // empty if Protect API not available
  const char* protect_user_id;    // empty if no X-UserId discovered
  const char* event_log_path;     // value of --event_log; empty if disabled
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

// Run `apt-get update` against the recorder's sources.list only.  Used by
// /api/refresh_apt and /api/channel after a channel switch -- duplicating
// the flag list keeps both endpoints consistent.
std::pair<int, std::string> run_apt_update_recorder_only() {
  std::string out;
  int rc = run_cmd(
      "apt-get update "
      "-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/onvif-recorder.list "
      "-o Dir::Etc::sourceparts=- "
      "-o APT::Get::List-Cleanup=0",
      &out);
  if (rc != 0) return {500, "apt update failed: " + out};
  return {200, "package list refreshed"};
}

// Handle POST /api/refresh_apt -- the standalone "Refresh package list"
// button.  Issue #28 confused users who ran `apt-get install --only-upgrade`
// without `apt-get update` first; this exposes the refresh as an explicit
// UI action so they can see when the cache was last updated.
std::pair<int, std::string> handle_refresh_apt(const Ctx&) {
  LOG(INFO) << "[admin] refreshing apt package list";
  return run_apt_update_recorder_only();
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

// Build JSON for GET /api/config: schema + override values + flag defaults.
std::string build_config_json(const Ctx& ctx) {
  auto overrides = runtime_config::ReadFromFile(ctx.config_path);

  std::string j = "{\"entries\":[";
  bool first = true;
  for (const auto& e : runtime_config::Schema()) {
    if (!first) j += ',';
    first = false;
    const char* type_str = "string";
    switch (e.type) {
      case runtime_config::Type::Bool:    type_str = "bool";    break;
      case runtime_config::Type::Int:     type_str = "int";     break;
      case runtime_config::Type::UInt16:  type_str = "uint16";  break;
      case runtime_config::Type::String:  type_str = "string";  break;
    }
    std::string flag_default;
    auto* flag = absl::FindCommandLineFlag(e.name);
    if (flag != nullptr) flag_default = flag->CurrentValue();
    j += "{\"name\":\"";    j += json_escape(e.name);
    j += "\",\"type\":\"";  j += type_str;
    j += "\",\"description\":\""; j += json_escape(e.description);
    j += "\",\"group\":\""; j += json_escape(e.group);
    j += "\",\"flag_default\":\""; j += json_escape(flag_default);
    j += "\",\"override\":\"";
    auto it = overrides.find(e.name);
    j += json_escape(it != overrides.end() ? it->second : std::string());
    j += "\"}";
  }
  j += "]}";
  return j;
}

// Build JSON for GET /api/camera_health.  Single DB round-trip via
// unifi::load_camera_health; emits one row per adopted camera with last
// event time and 1-hour event count.
std::string build_camera_health_json(const Ctx& ctx) {
  const uint64_t now_ms = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count());
  std::string j = "{\"now_ms\":";
  j += std::to_string(now_ms);
  j += ",\"cameras\":[";
  if (ctx.db == nullptr) {
    j += "]}";
    return j;
  }
  auto rows_or = unifi::load_camera_health(*ctx.db);
  if (!rows_or.ok()) {
    LOG(WARNING) << "[admin] load_camera_health: "
                 << rows_or.status().message();
    j += "]}";
    return j;
  }
  bool first = true;
  for (const auto& r : *rows_or) {
    if (!first) j += ',';
    first = false;
    j += "{\"id\":\"";   j += json_escape(r.id);
    j += "\",\"name\":\""; j += json_escape(r.name);
    j += "\",\"host\":\""; j += json_escape(r.host);
    j += "\",\"mac\":\"";  j += json_escape(r.mac);
    j += "\",\"is_third_party\":";
    j += r.is_third_party ? "true" : "false";
    j += ",\"last_event_ms\":";
    j += std::to_string(r.last_event_ms);
    j += ",\"events_1h\":";
    j += std::to_string(r.events_1h);
    j += "}";
  }
  j += "]}";
  return j;
}

// Build JSON for GET /api/recent_events.  Calls unifi::load_recent_events
// and shapes the rows for the admin UI.  Each row carries a
// `thumbnail_url` that the UI can drop into <img src=...>; empty when the
// thumbnail isn't in the DB (MSR-stored events show a placeholder).
std::string build_recent_events_json(const Ctx& ctx) {
  std::string j = "{\"events\":[";
  if (ctx.db == nullptr) {
    j += "]}";
    return j;
  }
  auto rows_or = unifi::load_recent_events(30, *ctx.db);
  if (!rows_or.ok()) {
    LOG(WARNING) << "[admin] load_recent_events: "
                 << rows_or.status().message();
    j += "]}";
    return j;
  }
  bool first = true;
  for (const auto& r : *rows_or) {
    if (!first) j += ',';
    first = false;
    j += "{\"id\":\"";   j += json_escape(r.id);
    j += "\",\"type\":\""; j += json_escape(r.type);
    j += "\",\"camera_id\":\""; j += json_escape(r.camera_id);
    j += "\",\"camera_name\":\""; j += json_escape(r.camera_name);
    j += "\",\"thumbnail_id\":\""; j += json_escape(r.thumbnail_id);
    j += "\",\"sdt\":";
    j += r.smart_detect_types_json.empty()
             ? std::string("[]")
             : r.smart_detect_types_json;
    j += ",\"start_ms\":"; j += std::to_string(r.start_ms);
    j += ",\"end_ms\":";   j += std::to_string(r.end_ms);
    j += ",\"thumbnail_in_db\":";
    j += r.thumbnail_in_db ? "true" : "false";
    j += "}";
  }
  j += "]}";
  return j;
}

// Build JSON for GET /api/first_party_cameras.
std::string build_first_party_json(const Ctx& ctx) {
  std::string j = "{\"cameras\":[";
  if (ctx.db == nullptr) {
    j += "]}";
    return j;
  }
  auto cams_or = unifi::load_all_first_party(*ctx.db);
  if (!cams_or.ok()) {
    LOG(WARNING) << "[admin] load_all_first_party: "
                 << cams_or.status().message();
    j += "]}";
    return j;
  }
  bool first = true;
  for (const auto& c : *cams_or) {
    if (!first) j += ',';
    first = false;
    j += "{\"id\":\"";   j += json_escape(c.id);
    j += "\",\"name\":\""; j += json_escape(c.name);
    j += "\",\"mac\":\"";  j += json_escape(c.mac);
    j += "\"}";
  }
  j += "]}";
  return j;
}

// Handle POST /api/config — body is a JSON object of name->string values.
// Validates each value against its schema entry, writes the file, then
// signals SIGTERM to ourselves so systemd restarts the service with the
// new overrides applied.
std::pair<int, std::string> handle_config(const Ctx& ctx,
                                          const std::string& body) {
  std::map<std::string, std::string> values;
  for (const auto& e : runtime_config::Schema()) {
    std::string raw = json_string_field(body, e.name);
    // Validate non-empty values against the flag's parser.
    if (!raw.empty()) {
      auto* flag = absl::FindCommandLineFlag(e.name);
      if (flag == nullptr) continue;  // schema/flag mismatch -- skip
      std::string err;
      // ParseFrom mutates the flag, but we only call it for validation.
      // The change is overwritten on the next process restart by
      // LoadFromFile reading the persisted JSON.
      if (!flag->ParseFrom(raw, &err)) {
        return {400, std::string("invalid ") + e.name + ": " + err};
      }
    }
    values[e.name] = raw;
  }
  auto s = runtime_config::WriteToFile(ctx.config_path, values);
  if (!s.ok()) return {500, std::string(s.message())};

  // Detach a child to send SIGTERM after we've returned the response, so
  // the client sees a clean 200 before the service exits and systemd
  // restarts it.
  pid_t self = getpid();
  if (fork() == 0) {
    // Child: brief delay then signal the parent.
    sleep(1);
    kill(self, SIGTERM);
    _exit(0);
  }
  return {200, "saved; service is restarting"};
}

// Build a tar.gz diagnostic archive in @p out_path.  Contents:
//   - config.json        copy of /etc/onvif-recorder/config.json
//   - status.json        output of /api/status
//   - camera_health.json output of /api/camera_health
//   - journal.log        journalctl -u onvif-recorder --since "12 hours ago"
//   - journal-prev.log   journalctl -u onvif-recorder -b -1 (previous boot)
//   - service-status.txt systemctl status onvif-recorder
//   - raw-onvif.jsonl    in-memory ring of recent SOAP exchanges (always on)
//   - event-log.jsonl    tail of --event_log file (last 5000 lines) if set
//   - nginx-error.log    tail of /var/log/nginx/error.log
//   - dpkg.txt           dpkg-query -W onvif-recorder, unifi-protect, etc.
//   - system.txt         uname -a, /sys/firmware/devicetree/base/model, free, df
// Returns ok status when the tarball exists at out_path.
absl::Status build_diagnostic_dump(const Ctx& ctx,
                                   const std::string& out_path) {
  char tmpl[] = "/tmp/onvif-dump.XXXXXX";
  if (mkdtemp(tmpl) == nullptr)
    return absl::InternalError("mkdtemp failed");
  const std::string dir = tmpl;

  // One sanitiser shared across every file in this dump so a given IP /
  // credential maps to the same redacted value across files.
  DumpSanitizer san;

  // Helper: sanitise then write content to a file inside dir.
  auto write = [&dir, &san](const char* name, const std::string& content) {
    std::ofstream f(dir + "/" + name, std::ios::binary | std::ios::trunc);
    if (f.is_open()) f << san.sanitize(content);
  };
  // Helper: capture the stdout of a shell command into a sanitised file.
  // 8 MiB cap per file keeps a verbose 12-hour journal intact (journald
  // averages ~150 B/line on this service so 8 MiB ≈ 50 k lines) while
  // still bounding worst-case memory.
  auto capture = [&dir, &san](const char* name, const std::string& cmd) {
    std::string out;
    run_cmd(cmd, &out, 8 * 1024 * 1024);
    std::ofstream f(dir + "/" + name, std::ios::binary | std::ios::trunc);
    if (f.is_open()) f << san.sanitize(out);
  };

  write("config.json",
        read_file(ctx.config_path ? ctx.config_path : ""));
  write("status.json", build_status_json(ctx));
  write("camera_health.json", build_camera_health_json(ctx));
  // 12h window covers the typical "I noticed it broke this morning" report
  // without blowing past journald's default retention on UDM.
  capture("journal.log",
          "journalctl -u onvif-recorder --since '12 hours ago' "
          "--no-pager 2>/dev/null");
  // Previous-boot journal — invaluable when the service crashed and is
  // the very thing the user is reporting.  Falls back gracefully if
  // there is no prior boot recorded.
  capture("journal-prev.log",
          "journalctl -u onvif-recorder -b -1 --no-pager 2>/dev/null "
          "|| echo '(no previous boot recorded)'");
  capture("service-status.txt",
          "systemctl status onvif-recorder --no-pager -l 2>/dev/null");
  capture("nginx-error.log",
          "tail -n 500 /var/log/nginx/error.log 2>/dev/null "
          "|| echo '(nginx error log not readable)'");
  // Raw ONVIF SOAP exchange log — sourced from the always-on in-memory
  // ring (see RawSink in onvif_listener).  No flag required: the dump
  // always contains the most recent ~1000 exchanges (~8 MiB cap).
  // --raw_log additionally tees to disk for long-form captures.
  write("raw-onvif.jsonl", RawSink::instance().snapshot());
  // Parsed-event log (--event_log) is still file-based; tail last 5000
  // lines when the flag is set, skip silently otherwise.
  if (ctx.event_log_path && ctx.event_log_path[0] != '\0') {
    capture("event-log.jsonl",
            std::string("tail -n 5000 ") + ctx.event_log_path
            + " 2>/dev/null || echo '(file not readable: "
            + ctx.event_log_path + ")'");
  }
  capture("dpkg.txt",
          "dpkg-query -W -f='${Package} ${Version}\\n' "
          "onvif-recorder unifi-protect unifi-core uos 2>/dev/null");
  capture("system.txt",
          "uname -a; "
          "echo '---'; "
          "cat /sys/firmware/devicetree/base/model 2>/dev/null; "
          "echo; "
          "free -h 2>/dev/null; "
          "echo '---'; "
          "df -h /var /srv 2>/dev/null");

  // Note in the archive that sanitisation was applied -- so a recipient
  // sees obviously redacted values and knows IP remapping is consistent
  // within this dump but not across dumps.
  {
    std::ofstream f(dir + "/SANITIZED.txt",
                    std::ios::binary | std::ios::trunc);
    if (f.is_open()) {
      f << "This archive was sanitised before tarballing.\n"
        << "  - IPv4 addresses are remapped via a per-prefix counter\n"
        << "    (1.1.1.1, 1.1.1.2, 1.1.2.1, ...) so the same source IP\n"
        << "    maps to the same value across files in this dump.\n"
        << "  - Usernames, passwords, password digests, nonces, URL\n"
        << "    credentials, Basic auth headers, and the X-UserId\n"
        << "    Protect bypass token are replaced with [REDACTED].\n"
        << "  - The mapping is regenerated for every dump, so values in\n"
        << "    different archives are NOT comparable.\n";
    }
  }

  const std::string cmd = "tar czf " + out_path + " -C " + dir + " . "
                          "&& rm -rf " + dir;
  std::string out;
  int rc = run_cmd(cmd, &out);
  if (rc != 0)
    return absl::InternalError("tar/rm failed: " + out);
  return absl::OkStatus();
}

// Read a binary file fully into a string.
std::string read_file_binary(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f.is_open()) return {};
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
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
  } else if (is_get &&
             std::strcmp(url, "/api/config") == 0) {
    body = build_config_json(*ctx);
    content_type = "application/json";
  } else if (is_get &&
             std::strcmp(url, "/api/first_party_cameras") == 0) {
    body = build_first_party_json(*ctx);
    content_type = "application/json";
  } else if (is_get &&
             std::strcmp(url, "/api/camera_health") == 0) {
    body = build_camera_health_json(*ctx);
    content_type = "application/json";
  } else if (is_get &&
             std::strcmp(url, "/api/recent_events") == 0) {
    body = build_recent_events_json(*ctx);
    content_type = "application/json";
  } else if (is_get &&
             std::strncmp(url, "/api/thumbnail", 14) == 0) {
    // /api/thumbnail?id=<thumb_id>.  IDs of length 24 live in the Protect
    // thumbnails table (read directly via libpq); other IDs are MSR-stored
    // UBV thumbnails which we proxy through Protect's local API at
    // <protect_url>/api/thumbnails/<id> using the cached X-UserId header.
    const char* qs = MHD_lookup_connection_value(
        connection, MHD_GET_ARGUMENT_KIND, "id");
    if (qs == nullptr || qs[0] == '\0') {
      status = 400;
      body = "missing id";
    } else {
      bool served = false;
      if (ctx->db != nullptr && std::strlen(qs) == 24) {
        auto bytes_or = unifi::load_thumbnail_bytes(qs, *ctx->db);
        if (!bytes_or.ok()) {
          status = 500;
          body = std::string(bytes_or.status().message());
          served = true;
        } else if (!bytes_or->empty()) {
          body.assign(reinterpret_cast<const char*>(bytes_or->data()),
                      bytes_or->size());
          content_type = "image/jpeg";
          served = true;
        }
      }
      if (!served) {
        std::string jpeg = fetch_protect_thumbnail(
            ctx->protect_url ? ctx->protect_url : "",
            ctx->protect_user_id ? ctx->protect_user_id : "",
            qs);
        if (!jpeg.empty()) {
          body = std::move(jpeg);
          content_type = "image/jpeg";
        } else {
          status = 404;
          body = "thumbnail not available";
        }
      }
    }
  } else if (is_get &&
             std::strcmp(url, "/api/diagnostic_dump") == 0) {
    const std::string tar_path = "/tmp/onvif-dump.tar.gz";
    auto s = build_diagnostic_dump(*ctx, tar_path);
    if (!s.ok()) {
      status = 500;
      body = std::string(s.message());
    } else {
      body = read_file_binary(tar_path);
      std::remove(tar_path.c_str());
      content_type = "application/gzip";
    }
  } else if (is_get &&
             std::strcmp(url, "/api/mallocz") == 0) {
    // tcmalloc heap stats — direct dump from MallocExtension.
    // Free; reads atomic counters maintained by the allocator.
    char buf[16384];
    MallocExtension::instance()->GetStats(buf, sizeof(buf));
    body = buf;
    content_type = "text/plain; charset=utf-8";
  } else if (is_get &&
             std::strcmp(url, "/api/contentionz") == 0) {
    // Per-mutex contention stats from the always-on absl::Mutex
    // tracer.  Format: fixed-width text table.
    body = ContentionProfiler::instance().snapshot();
    content_type = "text/plain; charset=utf-8";
  } else if (is_post) {
    auto* pc = static_cast<PostCtx*>(*con_cls);
    const std::string& pb = pc->body;
    std::pair<int, std::string> r{404, "not found"};
    if (std::strcmp(url, "/api/channel") == 0)
      r = handle_channel(*ctx, pb);
    else if (std::strcmp(url, "/api/check") == 0)
      r = handle_check();
    else if (std::strcmp(url, "/api/refresh_apt") == 0)
      r = handle_refresh_apt(*ctx);
    else if (std::strcmp(url, "/api/autoupdate") == 0)
      r = handle_autoupdate(pb);
    else if (std::strcmp(url, "/api/config") == 0)
      r = handle_config(*ctx, pb);
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
                        uint16_t port,
                        const std::string& config_path,
                        const unifi::DbConfig& db,
                        const std::string& protect_url,
                        const std::string& protect_user_id,
                        const std::string& event_log_path) {
  version_ = version;
  channel_file_ = channel_file;
  config_path_ = config_path;
  db_ = db;
  protect_url_ = protect_url;
  protect_user_id_ = protect_user_id;
  event_log_path_ = event_log_path;

  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  // Leaked Ctx: one per server instance; lives for the program lifetime.
  auto* ctx = new Ctx{version_.c_str(), channel_file_.c_str(),
                      config_path_.c_str(), &db_,
                      protect_url_.c_str(), protect_user_id_.c_str(),
                      event_log_path_.c_str()};

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
