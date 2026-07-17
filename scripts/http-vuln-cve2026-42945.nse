local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local string = require "string"

description = [[
Performs a safe, detection-only check for CVE-2026-42945 (NGINX Rift), a
heap-based buffer overflow in ngx_http_rewrite_module. The script classifies
likely vulnerability from reported NGINX version information and does not
attempt exploitation.
]]

---
-- @usage
-- nmap -p 80,443 --script http-vuln-cve2026-42945 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2026-42945:
-- |   VULNERABLE:
-- |   NGINX ngx_http_rewrite_module Heap Buffer Overflow (NGINX Rift)
-- |     State: LIKELY VULNERABLE
-- |     IDs:  CVE:CVE-2026-42945
-- |     Risk factor: HIGH
-- |     CVSSv4: 9.2
-- |     Description:
-- |       NGINX Open Source 0.6.27 through 1.30.0...
-- |     Disclosure date: 2026-05-13
-- |     References:
-- |       https://my.f5.com/manage/s/article/K000161019
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2026-42945
---

author = "Ishaan Jindal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function parse_version(ver_str)
  if type(ver_str) ~= "string" or not ver_str:match("^%d+%.%d+[%d%.]*$") then
    return nil
  end

  local parts = {}
  for part in string.gmatch(ver_str, "%d+") do
    parts[#parts + 1] = tonumber(part)
  end

  if #parts < 2 then
    return nil
  end

  return parts
end

local function version_lt(a, b)
  for i = 1, math.max(#a, #b) do
    local pa, pb = a[i] or 0, b[i] or 0
    if pa < pb then return true end
    if pa > pb then return false end
  end
  return false
end

local function version_gte(a, b)
  return not version_lt(a, b)
end

local function get_server_header(response)
  if not response or type(response.header) ~= "table" then
    return nil
  end

  return response.header["server"] or response.header["Server"]
end

local function extract_nginx_version(server_header)
  if type(server_header) ~= "string" then
    return nil
  end

  return server_header:match("^%s*[Nn][Gg][Ii][Nn][Xx]/([%d%.]+)%f[^%d%.]")
end

local function extract_port_version(port)
  if not port or type(port.version) ~= "table" then
    return nil
  end

  local product = port.version.product
  local version = port.version.version
  if type(product) ~= "string" or type(version) ~= "string" then
    return nil
  end

  if not product:lower():find("nginx", 1, true) then
    return nil
  end

  return version
end

local function fetch_response(host, port, path)
  local response = http.head(host, port, path, { bypass_cache = true })
  if not response or not response.status or response.status == 405 then
    response = http.get(host, port, path, { bypass_cache = true })
  end
  return response
end

action = function(host, port)
  local vuln = {
    title = "NGINX ngx_http_rewrite_module Heap Buffer Overflow (NGINX Rift)",
    state = vulns.STATE.NOT_VULN,
    description = [[
NGINX Open Source 0.6.27 through 1.30.0 and NGINX Plus R32 through R36 are
vulnerable to a heap-based buffer overflow in the ngx_http_rewrite_module.
When a rewrite directive uses unnamed PCRE captures with a question mark in
the replacement string, a length-calculation error leads to a heap buffer
overflow, potentially allowing denial of service or remote code execution.
    ]],
    IDS = {
      CVE = "CVE-2026-42945"
    },
    risk_factor = "HIGH",
    scores = {
      CVSSv4 = "9.2"
    },
    references = {
      "https://my.f5.com/manage/s/article/K000161019",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-42945",
      "https://labs.cloudsecurityalliance.org/research/csa-research-note-nginx-rift-cve-2026-42945-unauthenticated/"
    },
    dates = {
      disclosure = { year = "2026", month = "05", day = "13" }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local response = fetch_response(host, port, "/")
  if not response or not response.status then
    return vuln_report:make_output(vuln)
  end

  local server_header = get_server_header(response)
  local ver_str = extract_nginx_version(server_header)
  local source = "Server header"
  local port_ver_str = extract_port_version(port)

  if not ver_str and port_ver_str then
    ver_str = port_ver_str
    source = "service detection"
  elseif ver_str and port_ver_str and ver_str ~= port_ver_str then
    return vuln_report:make_output(vuln)
  end

  if not ver_str then
    return vuln_report:make_output(vuln)
  end

  local ver = parse_version(ver_str)
  if not ver then
    return vuln_report:make_output(vuln)
  end

  local min_ver = parse_version("0.6.27")
  local max_fixed_ver = parse_version("1.30.1")
  if version_gte(ver, min_ver) and version_lt(ver, max_fixed_ver) then
    vuln.state = vulns.STATE.LIKELY_VULN
    vuln.check_results = string.format("Detected nginx version %s (%s).", ver_str, source)
  end

  return vuln_report:make_output(vuln)
end
