# ThousandEyes Internal AJAX API Reference

## Base URL
All endpoints are relative to `https://app.thousandeyes.com`.

## Authentication
- Same-origin requests with session cookies (JSESSIONID)
- CSRF token from `XSRF-TOKEN` cookie → sent as `X-XSRF-TOKEN` header
- Content-Type: `application/json`

---

## Test Creation Endpoints

### HTTP Server Test
- **Endpoint:** `POST /ajax/tests/http-server`
- **Key fields:**
  - `url: { url: "https://example.com" }` — full URL with protocol
  - `freqHttp: 300` — interval in seconds
  - `testType: "Http"`
  - `httpVersion: 2`
  - `requestMethod: "GET"`
  - `sslVersion: 0`
  - `targetResponseTime: 1000`
  - `httpTimeLimit: 5`
  - `maxRedirects: 10`
  - `authType: "NONE"`
  - `flagVerifyCertHostname: 1`

### Agent-to-Server (Network) Test
- **Endpoint:** `POST /ajax/tests/network`
  - ⚠️ NOT `/ajax/tests/agent-to-server` (returns 404)
- **Key fields:**
  - `server: { serverName: "hostname-or-ip", port: 443 }` — **object**, not a string
  - `protocol: "TCP"`
  - `dscp: 0` — required, Differentiated Services Code Point
  - `freqA2s: 120` — interval in seconds
  - `interval: 120` — also required
  - `freq: 120` — also required
  - `testType: "A2s"`
  - `flagIcmp: 0`
  - `flagBgp: 1`
  - `flagUsePublicBgp: 1`
  - `ipv6Policy: "USE_AGENT_POLICY"`
  - `pathtraceInSession: 1`
  - `probeMode: "AUTO"`
- **Notes:**
  - `server.serverName` must be a plain hostname or IP — strip `https://`, paths, etc.
  - If user provides `host:port`, extract port from it

### Page Load (Browserbot) Test
- **Endpoint:** `POST /ajax/tests/page-load`
- **Key fields:**
  - `url: { url: "https://example.com" }` — full URL with protocol
  - `freqPage: 300` — interval in seconds
  - `freqBrowserbot: 300` — **required**, minimum 120 seconds
  - `freqHttp: 300` — **required** (HTTP sub-layer)
  - `testType: "Page"`
  - `httpVersion: 2`
  - `pageLoadTimeLimit: 10`
  - `httpTimeLimit: 10`

### DNS Server Test
- **Endpoint:** `POST /ajax/tests/dns-server`
- **Key fields:**
  - `domain: "example.com"` — plain domain, no protocol/path
  - `freqDns: 300` — interval in seconds
  - `dnsQueryClass: "IN"`
  - `dnsTransportProtocol: "UDP"`
  - `recursiveQueries: 1`
  - `testType: "DnsServer"`
  - `servers: [{ serverName: "8.8.8.8" }]` — DNS servers to query

### DNS Trace Test
- **Endpoint:** `POST /ajax/tests/dns-trace`
- **Key fields:**
  - `domain: "example.com"` — plain domain, no protocol/path
  - `freqDns: 300`
  - `dnsQueryClass: "IN"`
  - `dnsTransportProtocol: "UDP"`
  - `testType: "DnsTrace"`

---

## Common Body Fields (all test types)

```json
{
  "name": "Test Name",
  "description": "",
  "flagAlertsEnabled": 1,
  "flagDeleted": 0,
  "flagEnabled": 1,
  "flagInstant": 0,
  "flagLocked": 0,
  "flagShared": 0,
  "flagSnapshot": 0,
  "labelsIds": null,
  "tagIds": [],
  "agentInterfaces": {},
  "agentSet": {
    "agentSetId": 0,
    "vAgentIds": [66, 317746],
    "vAgentsFlagEnabled": {}
  },
  "flagCloudMonitoring": 0,
  "flagRandomizedStartTime": 0,
  "flagAvailBw": 0,
  "flagContinuousMode": 0,
  "flagMtu": 0,
  "flagPing": 1,
  "numTraceroutes": 3,
  "probePacketRate": null,
  "flagBgp": 1,
  "flagUsePublicBgp": 1,
  "privateMonitorSet": { "monitorSetId": null, "bgpMonitors": [] },
  "ipv6Policy": "USE_AGENT_POLICY",
  "pathtraceInSession": 1,
  "probeMode": "AUTO",
  "accountBindings": ["1174496"]
}
```

---

## Test Read/Detail Endpoint
- **Pattern:** `GET /ajax/tests/{slug}/{aid}/{testId}`
- **Slugs by type:**
  - `Http` → `http-server`
  - `A2s` / `Network` → `network`
  - `Page` / `BrowserBot` → `page-load`
  - `DnsServer` → `dns-server`
  - `DnsTrace` → `dns-trace`
  - `Voip` → `voip`
  - `WebTransaction` → `web-transaction`
  - `Ftp` → `ftp`
  - `Dnssec` → `dnssec`
  - `Bgp` → `bgp`
  - `Sip` → `sip-server`

## Test Write (Update) Endpoint
- **Pattern:** `POST /ajax/tests/{slug}`
- Body is the full enriched test object with modifications
- `flagIgnoreWarnings: 0` should be included
- ALL numeric `freq*` and `interval` fields must be updated to new value

## Test Delete Endpoint
- **Pattern:** `DELETE /ajax/tests/{slug}/{aid}/{testId}`
- No body needed
- ⚠️ Do NOT use POST with `flagDeleted: 1` — causes 400 validation errors

---

## Test List Endpoint
- `GET /ajax/settings/tests/list` — returns all tests for the account group

## Agent Endpoints
- `GET /ajax/settings/tests/virtual-agents` — returns all virtual agents (enterprise + cloud)
  - Response: `{ vAgents: [...] }`
  - Each agent has: `vAgentId`, `displayName`, `primaryAid`, `countryId`, `location` (object with city/state/country), `flagEnabled`, etc.
  - ⚠️ Cloud agents do NOT have IP addresses in this endpoint
- `GET /ajax/settings/tests/physical-agents/enterprise` — returns physical enterprise agent status
  - Used to get `lastSeen`, `status` (ONLINE/OFFLINE), `osDeprecationState`

## Session Verification
- `GET /ajax/settings/tests/init` — verify session is active

## Test View URL
- Pattern: `/network-app-synthetics/views/?testId={testId}`

---

## Gotchas & Lessons Learned

1. **Network test `server` field is an object**, not a string: `{ serverName: "host", port: 443 }`
2. **`/ajax/tests/agent-to-server` does not exist** — use `/ajax/tests/network` instead
3. **Page-load tests need 3 freq fields:** `freqPage`, `freqBrowserbot` (min 120s), `freqHttp`
4. **DNS tests need plain domains** — strip `https://` and paths from user input
5. **A2S tests need `dscp: 0`** in addition to server/port/protocol
6. **A2S tests need `freq`, `interval`, AND `freqA2s`** all set
7. **Deleting tests requires HTTP DELETE method**, not POST with flagDeleted
8. **When editing tests**, all numeric freq/interval fields must be updated to prevent 400 errors
9. **Type field from list API** uses values like `Http`, `Network`, `BrowserBot`, `WebTransaction`, `OneWayNetwork`, `DnsServer`, `DnsTrace`, `Voip`, `Ftp`, `Sip`, `Api`
10. **Virtual agents `location`** can be a string or an object `{ city, state, country }`
