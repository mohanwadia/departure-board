#include <Adafruit_SSD1306.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>
#include <functional>

#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
#define SCREEN_ADDRESS 0x3C // Debugging: Change C to D

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
// ── Config ────────────────────────────────────────────────────────────────────
const char* WIFI_SSID     = "";
const char* WIFI_PASSWORD = "";
const char* DEV_ID        = "";
const char* API_KEY       = "";
const char* MDNS_NAME     = "ptv"; // portal at http://ptv.local
const int   NUM_ROWS      = 6;
const int   DEPS_PER_ROW  = 2;
const unsigned long REFRESH_MS = 20000; // 6 HTTPS calls per refresh

// ── Per-row saved config ──────────────────────────────────────────────────────
struct RowCfg {
  bool    set;
  int32_t routeId;
  int32_t routeType;
  int32_t stopId;
  int32_t dirId;
  char    label[8];
  char    dir3[4];
  char    routeName[48];
  char    stopName[48];
  char    dirName[40];
};

RowCfg cfg[NUM_ROWS];
long   depEpoch[NUM_ROWS][DEPS_PER_ROW];
int    depCount[NUM_ROWS];
bool   rowErr[NUM_ROWS];

Preferences prefs;
WebServer   server(80);
bool          needRefresh = true;
unsigned long lastRefresh = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────
void copyStr(char* dst, size_t n, const String& s) {
  strncpy(dst, s.c_str(), n - 1);
  dst[n - 1] = 0;
}

String urlEncode(const String& s) {
  String out;
  char buf[4];
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') out += c;
    else { snprintf(buf, sizeof(buf), "%%%02X", (uint8_t)c); out += buf; }
  }
  return out;
}

// ── Signing ───────────────────────────────────────────────────────────────────
String signRequest(const String& path) {
  byte hmac[20];
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)API_KEY, strlen(API_KEY));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)path.c_str(), path.length());
  mbedtls_md_hmac_finish(&ctx, hmac);
  mbedtls_md_free(&ctx);

  String sig = "";
  for (int i = 0; i < 20; i++) {
    if (hmac[i] < 0x10) sig += "0";
    sig += String(hmac[i], HEX);
  }
  sig.toUpperCase();
  return sig;
}

String buildUrl(const String& endpoint) {
  String sep = (endpoint.indexOf('?') >= 0) ? "&" : "?";
  String path = endpoint + sep + "devid=" + DEV_ID;
  return "https://timetableapi.ptv.vic.gov.au" + path + "&signature=" + signRequest(path);
}

String lastErr;

bool ptvGet(const String& endpoint, JsonDocument& doc, const JsonDocument& filter) {
  lastErr = "";
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.useHTTP10(true);
  http.setTimeout(15000);
  if (!http.begin(client, buildUrl(endpoint))) { lastErr = "begin failed"; return false; }

  int code = http.GET();
  if (code != 200) {
    lastErr = "PTV HTTP " + String(code);
    Serial.println(lastErr + " for " + endpoint);
    http.end();
    return false;
  }
  DeserializationError err = deserializeJson(doc, http.getStream(),
                                             DeserializationOption::Filter(filter));
  http.end();
  if (err) {
    lastErr = "JSON error: " + String(err.c_str());
    Serial.println(lastErr);
    return false;
  }
  return true;
}

bool ptvEach(const String& endpoint, const char* wantKey,
             std::function<void(const String&)> onObj) {
  lastErr = "";
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  http.useHTTP10(true);
  http.setTimeout(15000);
  if (!http.begin(client, buildUrl(endpoint))) { lastErr = "begin failed"; return false; }

  int code = http.GET();
  if (code != 200) {
    lastErr = "PTV HTTP " + String(code);
    Serial.println(lastErr + " for " + endpoint);
    http.end();
    return false;
  }

  auto* s = http.getStreamPtr();
  int  total = http.getSize();
  long got = 0;
  unsigned long lastData = millis();
  uint8_t buf[512];

  int  depth = 0, capDepth = 0;
  bool inStr = false, esc = false, capturing = false, collectKey = false, arrMatch2 = false;
  bool isArr[8];
  memset(isArr, 0, sizeof(isArr));
  String capBuf, curKey, lastKey;
  capBuf.reserve(600);

  while (true) {
    int avail = s->available();
    if (avail > 0) {
      int n = s->readBytes(buf, avail < (int)sizeof(buf) ? avail : (int)sizeof(buf));
      lastData = millis();
      got += n;
      for (int i = 0; i < n; i++) {
        char c = (char)buf[i];
        if (inStr) {
          if (capturing) capBuf += c;
          if (esc) esc = false;
          else if (c == '\\') esc = true;
          else if (c == '"') {
            inStr = false;
            if (collectKey) { lastKey = curKey; collectKey = false; }
          } else if (collectKey && curKey.length() < 32) curKey += c;
          continue;
        }
        switch (c) {
          case '"':
            inStr = true;
            if (capturing) capBuf += c;
            else if (depth == 1) { collectKey = true; curKey = ""; }
            break;
          case '{':
          case '[':
            depth++;
            if (depth < 8) isArr[depth] = (c == '[');
            if (depth == 2 && c == '[') arrMatch2 = (lastKey == wantKey);
            if (capturing) capBuf += c;
            else if (c == '{' && depth == 3 && isArr[2] && arrMatch2) {
              capturing = true;
              capDepth = 3;
              capBuf = "{";
            }
            break;
          case '}':
          case ']':
            if (capturing) {
              capBuf += c;
              if (c == '}' && depth == capDepth) { capturing = false; onObj(capBuf); }
            }
            depth--;
            break;
          default:
            if (capturing) capBuf += c;
        }
        if (capturing && capBuf.length() > 4000) capturing = false;
      }
      if (total > 0 && got >= total) break;
    } else {
      if (total > 0 && got >= total) break;
      if (!s->connected()) break;
      if (millis() - lastData > 10000) {
        lastErr = "read timeout after " + String(got) + " bytes";
        http.end();
        return false;
      }
      delay(2);
    }
  }
  http.end();
  Serial.println("ptvEach " + endpoint + " -> " + String(got) + " bytes read, content-length " + String(total));
  if (got == 0) { lastErr = "empty response"; return false; }
  return true;
}

// ── Time ──────────────────────────────────────────────────────────────────────
long parseUtcEpoch(const char* iso) {
  if (!iso || strlen(iso) < 19) return 0;
  int yr = String(iso).substring(0, 4).toInt();
  int mo = String(iso).substring(5, 7).toInt();
  int dy = String(iso).substring(8, 10).toInt();
  int hr = String(iso).substring(11, 13).toInt();
  int mn = String(iso).substring(14, 16).toInt();
  int sc = String(iso).substring(17, 19).toInt();

  int y = yr, m = mo, d = dy;
  if (m <= 2) { y--; m += 9; } else { m -= 3; }
  long era  = (y >= 0 ? y : y - 399) / 400;
  int  yoe  = y - era * 400;
  int  doy  = (153 * m + 2) / 5 + d - 1;
  int  doe  = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  long days = era * 146097 + doe - 719468;
  return days * 86400L + hr * 3600L + mn * 60L + sc;
}

String minsLabel(long depEpoch, long nowEpoch) {
  long diff = depEpoch - nowEpoch;
  if (diff <= 30) return "Now";
  return String(diff / 60) + "m";
}

// ── Config persistence ────────────────────────────────────────────────────────
void rowKey(int i, char* buf) { sprintf(buf, "row%d", i); }

void loadConfig() {
  for (int i = 0; i < NUM_ROWS; i++) memset(&cfg[i], 0, sizeof(RowCfg));
  if (!prefs.begin("board", true)) return;
  for (int i = 0; i < NUM_ROWS; i++) {
    char k[8];
    rowKey(i, k);
    if (prefs.getBytesLength(k) == sizeof(RowCfg)) prefs.getBytes(k, &cfg[i], sizeof(RowCfg));
  }
  prefs.end();
}

void saveRow(int i) {
  char k[8];
  rowKey(i, k);
  prefs.begin("board", false);
  prefs.putBytes(k, &cfg[i], sizeof(RowCfg));
  prefs.end();
}

// ── Fetch next departures for one row ─────────────────────────────────────────
bool fetchRow(int i) {
  const RowCfg& c = cfg[i];
  String ep = "/v3/departures/route_type/" + String(c.routeType) +
              "/stop/" + String(c.stopId) +
              "/route/" + String(c.routeId) +
              "?direction_id=" + String(c.dirId) +
              "&max_results=" + String(DEPS_PER_ROW);

  JsonDocument filter;
  filter["departures"][0]["estimated_departure_utc"] = true;
  filter["departures"][0]["scheduled_departure_utc"] = true;

  JsonDocument doc;
  if (!ptvGet(ep, doc, filter)) return false;

  depCount[i] = 0;
  for (JsonObject d : doc["departures"].as<JsonArray>()) {
    if (depCount[i] >= DEPS_PER_ROW) break;
    const char* est = d["estimated_departure_utc"];
    const char* sch = d["scheduled_departure_utc"];
    const char* t = (est && est[0]) ? est : sch;
    if (!t) continue;
    depEpoch[i][depCount[i]++] = parseUtcEpoch(t);
  }
  return true;
}

// ── Draw ──────────────────────────────────────────────────────────────────────
void drawMessage(const String& l1, const String& l2 = "", const String& l3 = "") {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);
  display.setCursor(0, 0);  display.print(l1);
  display.setCursor(0, 12); display.print(l2);
  display.setCursor(0, 24); display.print(l3);
  display.display();
}

String padRight(const String& s, int w) {
  String o = s.substring(0, w);
  while ((int)o.length() < w) o += ' ';
  return o;
}
String padLeft(const String& s, int w) {
  String o = s;
  while ((int)o.length() < w) o = " " + o;
  return o;
}

String routeCode(const RowCfg& c) {
  if (c.routeType == 0 || c.routeType == 3) {
    const char* src = c.routeName[0] ? c.routeName : c.label;
    String out;
    for (const char* p = src; *p && out.length() < 3; p++) {
      if (isalpha((unsigned char)*p)) out += (char)toupper((unsigned char)*p);
    }
    return out;
  }
  return String(c.label).substring(0, 3);
}

String timeBlock(int i, long now) {
  String t1, t2;
  if (rowErr[i])             t1 = "err";
  else if (depCount[i] == 0) t1 = "--";
  else {
    t1 = minsLabel(depEpoch[i][0], now);
    if (depCount[i] > 1) t2 = minsLabel(depEpoch[i][1], now);
  }
  if (t1.length() > 3) return padRight(t1, 7);
  String b = (t2.length() && t2.length() <= 3) ? padLeft(t2, 3) : String("   ");
  return padLeft(t1, 3) + " " + b;
}

// One row = route(3) + space + destination(9) + space + times(7) = 21 chars
void drawBoard(long nowEpoch) {
  bool any = false;
  for (int i = 0; i < NUM_ROWS; i++) if (cfg[i].set) any = true;
  if (!any) {
    drawMessage("No rows set. Open:", WiFi.localIP().toString(), String(MDNS_NAME) + ".local");
    return;
  }

  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(SSD1306_WHITE);

  for (int i = 0; i < NUM_ROWS; i++) {
    if (!cfg[i].set) continue;
    String dest;
    for (const char* p = cfg[i].dirName; *p; p++) if ((uint8_t)*p < 0x80) dest += *p;

    String line = padRight(routeCode(cfg[i]), 3) + " " + padRight(dest, 9) + " " + timeBlock(i, nowEpoch);
    display.setCursor(0, i * 10);
    display.print(line);
  }
  display.display();
}

void refreshBoard() {
  long now = time(nullptr);
  if (now < 1000000) { drawMessage("Waiting for time..."); return; }

  for (int i = 0; i < NUM_ROWS; i++) {
    if (!cfg[i].set) continue;
    rowErr[i] = !fetchRow(i);
    server.handleClient();
  }
  drawBoard(time(nullptr));
}

void sendJson(JsonDocument& d) {
  String s;
  serializeJson(d, s);
  server.send(200, "application/json", s);
}

void handleConfigGet() {
  JsonDocument out;
  JsonArray arr = out.to<JsonArray>();
  for (int i = 0; i < NUM_ROWS; i++) {
    JsonObject o = arr.add<JsonObject>();
    o["set"]   = cfg[i].set;
    o["label"] = cfg[i].label;
    o["route"] = cfg[i].routeName;
    o["stop"]  = cfg[i].stopName;
    o["dir"]   = cfg[i].dirName;
  }
  sendJson(out);
}

template <typename T>
String jstr(const T& v) {
  const char* p = v.template as<const char*>();
  return p ? String(p) : String();
}

void streamList(const String& ep, const char* key,
                std::function<void(JsonDocument&, JsonDocument&)> mapFn) {
  String chunk;
  chunk.reserve(1600);
  bool started = false, first = true;

  bool ok = ptvEach(ep, key, [&](const String& s) {
    JsonDocument o;
    if (deserializeJson(o, s)) return;
    if (!started) {
      server.setContentLength(CONTENT_LENGTH_UNKNOWN);
      server.send(200, "application/json", "");
      started = true;
      chunk = "[";
    }
    JsonDocument r;
    mapFn(o, r);
    String piece;
    serializeJson(r, piece);
    if (!first) chunk += ',';
    first = false;
    chunk += piece;
    if (chunk.length() > 1200) { server.sendContent(chunk); chunk.remove(0); }
  });

  if (!started) {
    if (!ok) server.send(502, "text/plain", lastErr);
    else     server.send(200, "application/json", "[]");
    return;
  }
  chunk += "]";
  server.sendContent(chunk);
  server.sendContent("");
}

void handleAllRoutes() {
  streamList("/v3/routes", "routes", [](JsonDocument& o, JsonDocument& r) {
    r["id"]   = o["route_id"].as<long>();
    r["type"] = o["route_type"].as<int>();
    r["num"]  = jstr(o["route_number"]);
    r["name"] = jstr(o["route_name"]);
  });
}

void handleStops() {
  int rid = server.arg("route_id").toInt();
  int rt  = server.arg("route_type").toInt();
  String ep = "/v3/stops/route/" + String(rid) + "/route_type/" + String(rt) + "?stop_disruptions=false";
  streamList(ep, "stops", [](JsonDocument& o, JsonDocument& r) {
    r["id"]   = o["stop_id"].as<long>();
    r["name"] = jstr(o["stop_name"]);
    r["sub"]  = jstr(o["stop_suburb"]);
  });
}

void handleDirections() {
  int rid = server.arg("route_id").toInt();
  int rt  = server.arg("route_type").toInt();
  int sid = server.arg("stop_id").toInt();

  int served[10];
  int nServed = 0;
  if (sid > 0) {
    JsonDocument f2;
    f2["departures"][0]["direction_id"] = true;
    JsonDocument d2;
    String ep2 = "/v3/departures/route_type/" + String(rt) + "/stop/" + String(sid) +
                 "/route/" + String(rid) + "?max_results=20";
    if (ptvGet(ep2, d2, f2)) {
      for (JsonObject d : d2["departures"].as<JsonArray>()) {
        int id = d["direction_id"];
        bool seen = false;
        for (int k = 0; k < nServed; k++) if (served[k] == id) seen = true;
        if (!seen && nServed < 10) served[nServed++] = id;
      }
    }
  }

  JsonDocument out;
  JsonArray arr = out.to<JsonArray>();
  bool ok = ptvEach("/v3/directions/route/" + String(rid), "directions", [&](const String& s) {
    JsonDocument o;
    if (deserializeJson(o, s)) return;
    int id = o["direction_id"];
    bool serves = false;
    for (int k = 0; k < nServed; k++) if (served[k] == id) serves = true;
    JsonObject x = arr.add<JsonObject>();
    x["id"]     = id;
    x["name"]   = jstr(o["direction_name"]);
    x["serves"] = serves;
  });
  if (!ok) { server.send(502, "text/plain", lastErr); return; }
  sendJson(out);
}

void handleSave() {
  int row = server.arg("row").toInt();
  if (row < 0 || row >= NUM_ROWS) { server.send(400, "text/plain", "bad row"); return; }

  RowCfg c;
  memset(&c, 0, sizeof(c));
  c.set       = true;
  c.routeId   = server.arg("route_id").toInt();
  c.routeType = server.arg("route_type").toInt();
  c.stopId    = server.arg("stop_id").toInt();
  c.dirId     = server.arg("dir_id").toInt();
  copyStr(c.label,     sizeof(c.label),     server.arg("label"));
  copyStr(c.routeName, sizeof(c.routeName), server.arg("route_name"));
  copyStr(c.stopName,  sizeof(c.stopName),  server.arg("stop_name"));
  copyStr(c.dirName, sizeof(c.dirName), server.arg("dir_name"));

  cfg[row] = c;
  depCount[row] = 0;
  rowErr[row] = false;
  saveRow(row);
  needRefresh = true;
  server.send(200, "text/plain", "ok");
}

void handleClear() {
  int row = server.arg("row").toInt();
  if (row < 0 || row >= NUM_ROWS) { server.send(400, "text/plain", "bad row"); return; }
  memset(&cfg[row], 0, sizeof(RowCfg));
  depCount[row] = 0;
  saveRow(row);
  needRefresh = true;
  server.send(200, "text/plain", "ok");
}

// ── Portal page ───────────────────────────────────────────────────────────────
const char PAGE[] PROGMEM = R"HTML(<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PTV Board</title>
<style>
body{font-family:system-ui,sans-serif;margin:0;padding:12px;background:#f4f5f7;color:#111}
h1{font-size:1.1rem;margin:4px 0 12px}
#rows{max-width:1100px;margin:0 auto}
.r{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.r b{width:1.2em;text-align:center}
select{flex:1 1 170px;min-width:0;font:inherit;padding:7px;border:1px solid #bbb;border-radius:6px;background:#fff}
select:disabled{background:#eee;color:#777}
button{font:inherit;padding:7px 12px;border:0;border-radius:6px;background:#0a6;color:#fff;cursor:pointer}
button:disabled{background:#9bb;cursor:default}
button.sec{background:#888}
.msg{flex-basis:100%;font-size:.85rem;margin-left:1.6em}
</style></head><body>
<h1>PTV departure board</h1>
<div id="rows"></div>
<script>
const N=6,MODES=['Train','Tram','Bus','V/Line','Night Bus'];
const opt=(v,t)=>{const o=document.createElement('option');o.value=v;o.textContent=t;return o;};
async function get(u){const r=await fetch(u);const t=await r.text();if(!r.ok)throw new Error(t||('Request failed ('+r.status+')'));try{return JSON.parse(t);}catch(e){throw new Error('Bad response from board ('+t.length+' bytes): '+JSON.stringify(t.slice(0,160)));}}
let ROUTES=[],CFG=[];
const rows=[];
const routeText=r=>(r.num?r.num+' - ':'')+r.name+' ('+(MODES[r.type]||'')+')';

async function loadRoutes(){
  try{const c=JSON.parse(localStorage.getItem('ptvRoutes')||'null');if(c&&Date.now()-c.t<6048e5)return c.d;}catch(e){}
  const d=await get('/api/allroutes');
  d.sort((a,b)=>(a.num||a.name).localeCompare(b.num||b.name,undefined,{numeric:true}));
  try{localStorage.setItem('ptvRoutes',JSON.stringify({t:Date.now(),d}));}catch(e){}
  return d;
}
async function loadCfg(){try{CFG=await get('/api/config');}catch(e){}}

function mk(i){
  const el=document.createElement('div');el.className='r';
  el.innerHTML='<b>'+(i+1)+'</b><select class="route"></select><select class="stop"></select><select class="dir"></select><button class="save" disabled>Save</button><button class="clr sec">Clear</button><div class="msg"></div>';
  const $=s=>el.querySelector(s),R=$('.route'),S=$('.stop'),D=$('.dir'),SV=$('.save');
  let stops=[],dirs=[];
  const msg=(t,bad)=>{const m=$('.msg');m.textContent=t||'';m.style.color=bad?'#b00':'#060';};
  const ph=(sel,t,dis)=>{sel.replaceChildren(opt('',t));sel.disabled=dis!==false;};
  const cur=()=>CFG[i]||{};

  el.reset=()=>{
    const c=cur();
    ph(S,c.set?c.stop:'Stop');ph(D,c.set?c.dir:'Direction');
    R.replaceChildren(opt('',c.set?(c.label===c.route?c.label:c.label+' - '+c.route):(ROUTES.length?'Route':'Loading routes...')));
    ROUTES.forEach((r,k)=>R.appendChild(opt(k,routeText(r))));
    R.disabled=!ROUTES.length;SV.disabled=true;
  };

  R.onchange=async()=>{
    SV.disabled=true;msg('');
    const r=ROUTES[R.value];
    if(!r){ph(S,cur().set?cur().stop:'Stop');ph(D,cur().set?cur().dir:'Direction');return;}
    ph(S,'Loading stops...');ph(D,'Direction');
    try{
      stops=await get('/api/stops?route_id='+r.id+'&route_type='+r.type);
      stops.sort((a,b)=>a.name.localeCompare(b.name));
      S.replaceChildren(opt('','Stop'));
      stops.forEach((x,k)=>S.appendChild(opt(k,x.name+(x.sub?' ('+x.sub+')':'')+' #'+x.id)));
      S.disabled=false;
    }catch(e){ph(S,'Stop');msg(e.message,1);}
  };

  S.onchange=async()=>{
    SV.disabled=true;msg('');
    const r=ROUTES[R.value],s=stops[S.value];
    if(!s){ph(D,'Direction');return;}
    ph(D,'Loading directions...');
    try{
      dirs=await get('/api/directions?route_id='+r.id+'&route_type='+r.type+'&stop_id='+s.id);
      dirs.sort((a,b)=>b.serves-a.serves);
      D.replaceChildren(opt('','Direction'));
      dirs.forEach((x,k)=>D.appendChild(opt(k,x.name+(x.serves?'':' (no departures seen)'))));
      D.disabled=false;
    }catch(e){ph(D,'Direction');msg(e.message,1);}
  };

  D.onchange=()=>{SV.disabled=(D.value==='');};

  SV.onclick=async()=>{
    const r=ROUTES[R.value],s=stops[S.value],d=dirs[D.value];
    const body=new URLSearchParams({row:i,route_id:r.id,route_type:r.type,label:r.num||r.name,
      route_name:r.name,stop_id:s.id,stop_name:s.name,dir_id:d.id,dir_name:d.name});
    try{
      const res=await fetch('/api/save',{method:'POST',body});
      if(!res.ok)throw new Error('Save failed');
      await loadCfg();el.reset();msg('Saved');
    }catch(e){msg(e.message,1);}
  };

  $('.clr').onclick=async()=>{
    await fetch('/api/clear',{method:'POST',body:new URLSearchParams({row:i})});
    await loadCfg();el.reset();msg('Cleared');
  };
  return el;
}

const holder=document.getElementById('rows');
for(let i=0;i<N;i++){const r=mk(i);rows.push(r);holder.appendChild(r);}
(async()=>{
  await loadCfg();rows.forEach(r=>r.reset());
  try{ROUTES=await loadRoutes();}catch(e){holder.insertAdjacentText('afterbegin',e.message);}
  rows.forEach(r=>r.reset());
})();
</script></body></html>)HTML";

// ── Setup ─────────────────────────────────────────────────────────────────────
void setup() {
  Serial.begin(115200);

  if (!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS)) {
    Serial.println("SSD1306 failed");
    for (;;);
  }
  drawMessage("Connecting WiFi...");

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) { delay(500); }
  Serial.println("WiFi connected: " + WiFi.localIP().toString());

  configTime(0, 0, "pool.ntp.org");
  unsigned long t0 = millis();
  while (time(nullptr) < 1000000 && millis() - t0 < 10000) delay(200);

  if (MDNS.begin(MDNS_NAME)) MDNS.addService("http", "tcp", 80);

  loadConfig();

  server.on("/", HTTP_GET, []() { server.send_P(200, "text/html", PAGE); });
  server.on("/api/config",     HTTP_GET,  handleConfigGet);
  server.on("/api/allroutes",  HTTP_GET,  handleAllRoutes);
  server.on("/api/stops",      HTTP_GET,  handleStops);
  server.on("/api/directions", HTTP_GET,  handleDirections);
  server.on("/api/save",       HTTP_POST, handleSave);
  server.on("/api/clear",      HTTP_POST, handleClear);
  server.begin();

  drawMessage("Portal:", WiFi.localIP().toString(), String(MDNS_NAME) + ".local");
  delay(2500);
}

// ── Loop ──────────────────────────────────────────────────────────────────────
void loop() {
  server.handleClient();

  if (needRefresh || millis() - lastRefresh >= REFRESH_MS) {
    needRefresh = false;
    lastRefresh = millis();
    refreshBoard();
  }
}
