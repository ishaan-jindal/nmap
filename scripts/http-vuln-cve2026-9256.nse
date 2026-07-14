local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects NGINX servers vulnerable to CVE-2026-9256, a heap-based buffer
overflow in the ngx_http_rewrite_module. Affects NGINX Open Source 1.0.0
through 1.30.1 and version 1.31.0, and various NGINX Plus releases. An
unauthenticated attacker can trigger a heap buffer overflow via crafted
HTTP requests using overlapping PCRE captures.
]]

---
-- @usage
-- nmap -p 80,443 --script http-vuln-cve2026-9256 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-vuln-cve2026-9256:
-- |   VULNERABLE:
-- |   NGINX ngx_http_rewrite_module Heap Buffer Overflow
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2026-9256
-- |     Risk factor: HIGH
-- |     Description:
-- |       NGINX Open Source 1.0.0 through 1.30.1...
-- |     Disclosure date: 2026-05-22
-- |     References:
-- |       https://my.f5.com/manage/s/article/K000161377
-- |_      https://nvd.nist.gov/vuln/detail/CVE-2026-9256
---

author = "Ishaan Jindal"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function parse_version(ver_str)
  local parts = {}
  for part in string.gmatch(ver_str, "%d+") do
    parts[#parts + 1] = tonumber(part)
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

action = function(host, port)
  local vuln = {
    title = "NGINX ngx_http_rewrite_module Heap Buffer Overflow",
    state = vulns.STATE.NOT_VULN,
    description = [[
NGINX Open Source 1.0.0 through 1.30.1 and version 1.31.0 are vulnerable to
a heap-based buffer overflow in the ngx_http_rewrite_module. When a rewrite
directive uses a regex pattern with overlapping PCRE captures and a
replacement string referencing multiple captures, a heap buffer overflow can
occur, potentially allowing denial of service or remote code execution.
    ]],
    IDS = {
      CVE = "CVE-2026-9256"
    },
    risk_factor = "HIGH",
    references = {
      "https://my.f5.com/manage/s/article/K000161377",
      "https://nvd.nist.gov/vuln/detail/CVE-2026-9256"
    },
    dates = {
      disclosure = { year = "2026", month = "05", day = "22" }
    }
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local response = http.get(host, port, "/")
  if not response or not response.status then
    return vuln_report:make_output(vuln)
  end

  local server_header = response.header["server"]
  if not server_header then
    return vuln_report:make_output(vuln)
  end

  local ver_str = string.match(server_header, "nginx/([%d.]+)")
  if not ver_str then
    return vuln_report:make_output(vuln)
  end

  local ver = parse_version(ver_str)
  if #ver < 2 then
    return vuln_report:make_output(vuln)
  end

  -- Affected: 1.0.0 <= ver < 1.30.2, or ver == 1.31.0
  if version_gte(ver, parse_version("1.0.0")) and
     version_lt(ver, parse_version("1.30.2")) then
    vuln.state = vulns.STATE.VULN
  elseif ver[1] == 1 and ver[2] == 31 and (ver[3] or 0) == 0 then
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end
