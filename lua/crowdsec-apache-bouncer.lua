-- crowdsec-apache-bouncer
-- CrowdSec AppSec (WAF) remediation component for Apache httpd, running inside mod_lua.
--
-- Every initial request is submitted to a CrowdSec AppSec component (method, URI, Host, headers, client IP) before
-- Apache serves it. If the AppSec component asks to block, the request is answered with an HTTP error (403 by
-- default); otherwise Apache goes on as usual. On any failure (component unreachable, timeout, rejected API key)
-- the request is let through unless APPSEC_FAILURE_ACTION=deny.
--
-- Hook it with:  LuaHookAccessChecker /usr/share/crowdsec-apache-bouncer/crowdsec-apache-bouncer.lua check early
--
-- Limitation: the request body is not inspected. Reading it from an access checker consumes it, and the content
-- handler (PHP, proxy, CGI...) would then receive an empty body.
--
-- Copyright (c) 2026 Dorian. MIT License.

local http = require("socket.http")
local ltn12 = require("ltn12")

local VERSION = "0.1.0"
local CONFIG_PATH = os.getenv("CROWDSEC_APACHE_BOUNCER_CONFIG")
    or "/etc/crowdsec/bouncers/crowdsec-apache-bouncer.conf"
local CONFIG_TTL = 60 -- seconds between two reads of the configuration file

local DEFAULTS = {
  ENABLED = "true",
  APPSEC_URL = "http://127.0.0.1:7422/",
  API_KEY = "",
  APPSEC_TIMEOUT_MS = "500",
  APPSEC_FAILURE_ACTION = "passthrough",
  BLOCK_STATUS = "",
  EXCLUDE_LOCATION = "",
}

-- Hop-by-hop or body-related headers that must not be forwarded to the AppSec component (no body is sent).
local SKIP_HEADERS = {
  ["host"] = true, ["content-length"] = true, ["transfer-encoding"] = true, ["connection"] = true,
  ["keep-alive"] = true, ["te"] = true, ["trailer"] = true, ["upgrade"] = true, ["expect"] = true,
}

local cfg, cfg_loaded_at = nil, 0

local function trim(s)
  return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function split_list(s)
  local out = {}
  for item in s:gmatch("[^,%s]+") do
    out[#out + 1] = item
  end
  return out
end

-- Reads KEY=VALUE lines (# comments allowed). Keeps the previous configuration if the file cannot be read.
local function load_config(r)
  local now = os.time()
  if cfg and now - cfg_loaded_at < CONFIG_TTL then
    return cfg
  end
  local f, err = io.open(CONFIG_PATH, "r")
  if not f then
    if not cfg then
      r:err("crowdsec: cannot read " .. CONFIG_PATH .. ": " .. tostring(err) .. " (bouncer disabled)")
      cfg = { ENABLED = "false" }
    end
    cfg_loaded_at = now
    return cfg
  end
  local c = {}
  for k, v in pairs(DEFAULTS) do
    c[k] = v
  end
  for line in f:lines() do
    line = trim(line)
    if line ~= "" and line:sub(1, 1) ~= "#" then
      local k, v = line:match("^([%w_]+)%s*=%s*(.-)$")
      if k then
        c[k] = v
      end
    end
  end
  f:close()
  c.timeout = (tonumber(c.APPSEC_TIMEOUT_MS) or 500) / 1000
  c.exclude = split_list(c.EXCLUDE_LOCATION)
  c.deny_on_failure = c.APPSEC_FAILURE_ACTION:lower() == "deny"
  c.block_status = tonumber(c.BLOCK_STATUS)
  if c.API_KEY == "" then
    r:err("crowdsec: API_KEY is empty in " .. CONFIG_PATH .. " (bouncer disabled)")
    c.ENABLED = "false"
  end
  cfg, cfg_loaded_at = c, now
  return cfg
end

local function excluded(c, uri)
  for _, prefix in ipairs(c.exclude) do
    if uri == prefix or uri:sub(1, #prefix) == prefix then
      return true
    end
  end
  return false
end

-- Request headers as a Lua table (mod_lua >= 2.4.48 has r:headers_in_table()).
local function request_headers(r)
  local out = {}
  if r.headers_in_table then
    for k, v in pairs(r:headers_in_table()) do
      if not SKIP_HEADERS[k:lower()] then
        out[k] = v
      end
    end
  else
    for _, k in ipairs({ "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Referer", "Cookie",
                         "Content-Type", "Origin", "X-Requested-With", "Authorization" }) do
      local v = r.headers_in[k]
      if v then
        out[k] = v
      end
    end
  end
  return out
end

local FAILURE_LOG_INTERVAL = 60 -- seconds; one warning per thread and interval, not one per request
local failures_since_log, last_failure_log = 0, 0

local function failure(r, c, reason)
  failures_since_log = failures_since_log + 1
  local now = os.time()
  if now - last_failure_log >= FAILURE_LOG_INTERVAL then
    r:warn(string.format("crowdsec: AppSec check failed (%s), %s [%d failure(s) since last report]",
      reason, c.deny_on_failure and "denying" or "letting through", failures_since_log))
    failures_since_log, last_failure_log = 0, now
  end
  if c.deny_on_failure then
    return c.block_status or 403
  end
  return apache2.DECLINED
end

-- mod_lua access checker. Returns apache2.DECLINED to let Apache go on, or an HTTP status to block.
function check(r)
  if not r.is_initial_req then
    return apache2.DECLINED -- internal redirects and subrequests were already checked
  end
  local c = load_config(r)
  if c.ENABLED ~= "true" then
    return apache2.DECLINED
  end
  local uri = r.unparsed_uri or r.uri or "/"
  if excluded(c, r.uri or uri) then
    return apache2.DECLINED
  end

  local ip = r.useragent_ip or (r.connection and r.connection.client_ip) or ""
  local headers = request_headers(r)
  headers["X-Crowdsec-Appsec-Ip"] = ip
  headers["X-Crowdsec-Appsec-Uri"] = uri
  headers["X-Crowdsec-Appsec-Host"] = r.headers_in["Host"] or r.hostname or ""
  headers["X-Crowdsec-Appsec-Verb"] = r.method
  headers["X-Crowdsec-Appsec-User-Agent"] = r.headers_in["User-Agent"] or ""
  headers["X-Crowdsec-Appsec-Http-Version"] = (r.protocol or ""):match("HTTP/(%d%.?%d?)") or ""
  headers["X-Crowdsec-Appsec-Api-Key"] = c.API_KEY

  local chunks = {}
  -- socket.http applies its module-wide TIMEOUT to every socket operation, overriding any timeout set by a custom
  -- "create" function. The Lua state is not shared between threads (LuaScope thread), so setting it here is safe.
  http.TIMEOUT = c.timeout
  local ok, status = http.request({
    url = c.APPSEC_URL,
    method = "GET",
    headers = headers,
    sink = ltn12.sink.table(chunks),
  })
  if not ok then
    return failure(r, c, tostring(status))
  end
  if status == 200 then
    return apache2.DECLINED
  end
  if status == 401 then
    return failure(r, c, "API key rejected (401)")
  end
  if status ~= 403 then
    return failure(r, c, "unexpected status " .. tostring(status))
  end

  local body = table.concat(chunks)
  local action = body:match('"action"%s*:%s*"(%w+)"') or "ban"
  if action == "allow" then
    return apache2.DECLINED
  end
  local code = c.block_status or tonumber(body:match('"http_status"%s*:%s*(%d+)')) or 403
  r:notice(string.format("crowdsec: blocked %s %s from %s (AppSec action %s, status %d)",
    r.method, uri, ip, action, code))
  return code
end

-- Exposed for tests and diagnostics.
crowdsec_apache_bouncer_version = VERSION
