local http = require "http"
local shortport = require "shortport"
local vulns = require "vulns"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects NGINX servers vulnerable to CVE-2026-42945 (NGINX Rift), a
heap-based buffer overflow in the ngx_http_rewrite_module. Affects NGINX
Open Source 0.6.27 through 1.30.0 and NGINX Plus R32 through R36. An
unauthenticated attacker can trigger a heap buffer overflow via crafted
HTTP requests, leading to denial of service or potential code execution.
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
-- |     State: VULNERABLE
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

  if version_gte(ver, parse_version("0.6.27")) and
     version_lt(ver, parse_version("1.30.1")) then
    vuln.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln)
end
