# TE-Optics codebase map

Everything lives in `src/panel.js` (one ~30k-line IIFE that builds a big CSS
string in a template literal, then a lot of feature code). It's organized into
loosely-coupled subsystems. Anchor navigation by **function/const name +
`grep`** — line numbers drift with every edit.

## Table of contents
1. ThousandEyes domain glossary
2. The dashboard agent map (the world map)
3. Geocoding (local gazetteer — no external geocoder)
4. The fullscreen trace overlay
5. Device Layer / SNMP topology view
6. Endpoint-agent loading & the perf history
7. Markers, clustering, and layout
8. Performance playbook (patterns already established)
9. Data windows, versioning, misc

---

## 1. ThousandEyes domain glossary

- **Enterprise agents** — org-deployed probes (physical/virtual). Have configured
  lat/lng usually. `agentType === 'Enterprise'`.
- **Endpoint agents** — software on end-user machines. Thousands of them; carry a
  `location` string and sometimes `geoCoordinates`. Loaded via a paged search.
- **Cloud agents** — TE-hosted global probes. Shown as light-blue cloud icons,
  especially in the trace overlay as sources.
- **Tests** — SaaS/HTTP/DNS/Network/Agent-to-Agent (OneWayNetwork) etc. Each has
  agents that run it; each run has **rounds** (time buckets).
- **Path visualization / traceroute** — per-agent hop-by-hop path to a
  destination, with latency and loss. Backs the trace overlay.
- **Device Layer (SNMP)** — a separate TE product: DeviceDiscovery test →
  **devices** (`dmDeviceId`) → **interfaces** (`ifIndex`) → metrics. Devices join
  to polling agents via `device.deviceAgents[].vAgentId`.
- **Health / availability** — TE health scores (0–100) and availability %.
  `ENDPOINT_TEST_APPLICATION_SCORE` is (despite the name) a network-path
  loss/latency quality blend, used for the per-agent "Net" score. This is a
  DIFFERENT metric from per-test availability — a card's aggregate "Net %" can
  legitimately disagree with the per-test rows in its popover (different metric,
  scope, and time window).

## 2. The dashboard agent map (`renderDashboardAgentMap`)

The centerpiece: a world map (`TEP_BASEMAP`, an inline SVG basemap) with agent
markers. Two modes — inline (in the dashboard) and **fullscreen** (`full` flag,
`dashMapFullEl`), which is where the trace overlay + live test live.

Key pieces:
- `buildDashboardMapAgents()` — turns `agents` + endpoint agents into a plotted
  `list` (applies type/ISP/seen-window filters; search/alert/list-hover hits are
  *exempt* from filters so a searched agent is always plottable).
- `renderDashboardAgentMap(hostEl, opts)` — builds the wrap/svg/overlay, clusters
  the list, creates one marker `div` per cluster, wires hover/click, zoom/pan.
- `paintMarker(m)` — (re)paints a marker's shape/color/label from live data;
  called at build AND on in-place refreshes (`dashMapLivePaint`) so refreshes
  never rebuild the DOM or disturb zoom.
- Zoom/pan is **viewBox-based** (vector-crisp). `epDashMapZoom = {s, tx, ty}`
  shared between inline + fullscreen. `MIN=1, MAX=32` (max raised from 16 per
  user request). `animateZoomTo(target, duration, onDone)` eases pan/zoom;
  `cancelZoomAnim()` on manual input. `atMaxZoom = s >= MAX - 0.01`.
- `layoutMarkers()` — positions every marker per-frame during zoom/pan and runs
  overlap-avoidance (`nudgeApart`, O(n²), capped). Also positions the trace
  overlay elements. Has a cheaper mid-animation fast path.

Hover/click model on the fullscreen map:
- `mouseover` opens a hover card (`showTip`), with a linger-to-switch delay when
  another card is open. `mouseout` to blank schedules a hide.
- `pointerup` (click) is separate: single-agent marker → opens the agent; cluster
  → no-op (or, during a trace, pins isolation — see §4); blank map → clears trace.

## 3. Geocoding (local, no external geocoder)

TE's path-vis gives a `geonameId` + a human "City, Region, Country" string but no
lat/lng, and CSP blocks external geocoders — so resolution is **local**.

- **`geonameId` is deliberately NOT used** — it's not reliably per-source (a
  shared/generic id collapses unrelated agents onto one point). `locationName`
  text is the reliable signal.
- `TEP_GEO` — embedded gazetteer: `.cities` (`"city|cc"` → `[lat,lng]`), `.states`
  (US state centroids), `.countries`, `.cc` (country name → code).
- `METRO_COORDS` — curated city-precise metros (cloud/PoP cities), consulted
  first for destinations.
- `epGeocode(locationName)` — the general resolver. Order: city+country → US
  city/state → plain city → region-as-city → country centroid. Returns
  `{lat, lng, precision: 'city'|'region'|'country'}`.
- `liveTestResolveDestGeo(locationName)` — for trace destinations; accepts ONLY
  city precision (rejects region/country centroids as misleading generic points).
- `tepHopGeo(locationName)` — tries `liveTestResolveDestGeo`, then `epGeocode`
  accepting city/region/country as a last resort.
- **Ambiguity gotcha (fixed):** "Georgia" is both a US state and a country.
  `epGeocode` has a step-0 disambiguation mapping a bare state name (or "…, US"
  with no city) that collides with a country to the state's principal city
  (Georgia → Atlanta), gated so real country targets carrying a city
  ("Tbilisi, Georgia") and 3-part strings ("Georgia, Vermont") are untouched. If
  other state/country name collisions surface, extend `US_STATE_PRINCIPAL_CITY`.
- `tepReverseGeocode(lat, lng, cc)` — coords → "City, State/CC" label.

## 4. The fullscreen trace overlay

Draws each source agent's path to a test's destination as an animated line with
hop nodes and latency/loss tags. Lives in the fullscreen map.

State + builders:
- `dashMapSelectedTestDest` — the resolved destination info for the pinned/hovered
  test (`{testId, roundId, location, lat, lng, dests[], pathNodesByAgent Map,
  sourceNames/sourceAgentIds Sets, testName, …}`) or null.
- `tepResolveTestDestination(testId, isEndpoint, isOneWayNet, endpointRound)` —
  resolves a test's destination(s) from path-vis / eyebrow topology, walking back
  rounds until a round with a resolvable destination node exists. Cached in
  `dashMapTestDestCache`; failures recorded in `dashMapTestDestFail`.
- `testDestFlowLines[]` — per source→dest line:
  `{pathEl, glowEl, packetEl, hopEls[{el,hopFraction}], srcLabelEl, srcCloudEl,
  srcFx, srcFy, destFx, destFy}`. Built by `buildTestDestFlow()`; positioned each
  frame in `layoutMarkers`.
- `buildSelectedTestDest()` — marks source markers `tep-testdest-related` + draws
  dest pins.
- `tepShowTraceForTest(tid, ds, commit)` — resolve + draw a test's trace. Uses a
  **load-sequence token** (`tepTraceLoadSeq`) so a slow resolve that lands after
  the user moved on is dropped instead of stomping the newer trace;
  `tepAbortTraceLoad()` cancels an in-flight load (respects a `commit`ted click).
- Hover-to-trace lives in the SaaS/Network breakdown popovers: a row's locate pin
  shows a pulsing **"Tracing…"** state (`tep-testdest-locate--tracing`) while
  loading, then swaps to the **"Pin it"** glow (`--glow`) on success. Dwell =
  `TEP_TRACE_HOVER_DELAY_MS`.

Interaction:
- **Hover isolation**: hovering a source/hop isolates that one trace (others off)
  via `tep-trace-focusing` on the wrap + `tep-trace-focus` on the flow els
  (`tepFocusTraceSource`, `tepApplyTraceFocus`, `tepTraceFlowsForMarker`).
- **Click-to-pin**: clicking a source pins its isolation (`tracePinFocus`,
  `tepToggleTracePin`) — persists until you click it again or click blank map.
  `mouseout` reverts to the pinned set. Pin resets when flow lines rebuild.
- Latency tags sit **below** their nodes (source pill `top:20px`; hop tags
  `top: calc(100% + 18px)`) so the cursor/card don't cover them.
- `frameTestDest` (in `dashMapZoomHook`) frames the trace; the hover reposition is
  slow (2800ms = 1/4 speed) and **hard-caps zoom so every source agent — cloud
  agents included, via `testDestFlowLines` — stays on screen**.
- Loss is a static red ring (no strobe). Trace-draw CSS: `tep-flow-draw`,
  `tep-livetest-flow-dash`, comet `tep-livetest-packet`.

## 5. Device Layer / SNMP topology view

Surfaces TE Device-Layer (SNMP) devices in the cluster "subnet view" and a
per-subnet topology view.

- Inventory + topology fetched lazily (`tepFetchSnmpInventory`,
  `tepFetchDeviceTopology`); silently no-ops when the account has no Device Layer
  license (`tepSnmpInvUnavailable`).
- Endpoints (paths/shapes only — see memory file `snmp-device-layer-api.md`):
  `…/round-data/{round}/topology` (nodes+edges+live metrics),
  `…/round-data/{round}/interfaces` (physical ports, ifType 6),
  `monitoredInterfaceIdsByMonitoredDeviceId`.
- Topology view: `tepOpenDeviceTopoView(cluster, label)`, node model in
  `tepBuildDeviceTopoModel`-style code; gateway detection scores default-gw IP
  (.1), name keywords, kind, LLDP position; BFS roots at the gateway.
- **Switch faceplates**: `tepDevicePorts` builds the port model (physical ports,
  ifType 6, colored by state; WAN/port-0 is an exclusive slot, not in the numbered
  grid). `tepDeviceFaceplateHtml` renders a 2-row grid; **caps at 24 cells** — a
  high-density switch (48/96 ports) collapses consecutive ports into equal groups
  (`96 → 24 cells of 4`, "Ports 1–4") with aggregate state + N/M-up tooltip.
- Subnet-view modal (`openClusterMaxView`) **sizes to its data**: width fits the
  subnet columns (capped + centered), height fits the tallest column; the
  grow-from-button animation reads the real size via `offsetWidth/offsetHeight`
  (getBoundingClientRect would read the `scale(.05)` start size).
- Deep links: `tepDeviceLayerUrl(deviceId)` → TE Device-Layer UI;
  `tepDeviceClientsUrl` → the TE Endpoint Agents page ("Clients").

## 6. Endpoint-agent loading & the perf history

- Roster comes from `ENDPOINT_AGENT_SEARCH_PATH` =
  `/namespace/endpoint-api/agent-management-service/v3/agent/management/metadata/search`
  — carries `geoCoordinates{latitude, longitude, cityName}` and supports offset
  paging (`?page=N&pageSize=100`) AND cursor `searchAfter`. (The sibling
  `settings/search` is battery-only, no coords.)
- `fetchEndpointAgentsViaSearch({onPage})` — page 0 gets `totalCount`, probes
  page 1 for duplicates; if offset paging works, fans out parallel workers
  (concurrency ~6); else falls back to `fetchEndpointAgentsCursor`. Progressive
  render as pages arrive. This fixed a "1000+ agents load slowly" complaint —
  the native UI is fast because it pages in parallel. `MAX_ENDPOINT_AGENTS = 5000`
  hard cap. See memory file `endpoint-agent-map-perf.md`.

## 7. Markers, clustering, and layout

- **Clustering** is a fixed geographic radius: `CLUSTER_MI = 5` — agents within 5
  miles merge into one marker, computed once at build (O(n²) over clusters). This
  is **zoom-independent**, so at world zoom you get the maximum marker count
  exactly when they're most crowded. (Known next perf lever: screen-pixel /
  zoom-aware clustering — see §8.)
- Each cluster → one marker `div` with an SVG icon, badge (agent count),
  gradient, box-shadow, health ring, optional latency label.
- Online markers "breathe" (`tep-marker-breathe` infinite + `will-change`).
- Overlap avoidance in `layoutMarkers` (`nudgeApart`): full separation
  (measured boxes, COVER=1) is broadened to any zoomed-in view via
  `spreadTraceLabels` (`s >= 3`), not just absolute max zoom.

## 8. Performance playbook (patterns already established)

The map/trace overlays can peg the GPU/compositor at scale. Established fixes,
and the reasoning — reuse these patterns:

- **The compositor-layer trap.** `will-change` on *many* elements forces a
  separate GPU layer each; hundreds of forever-animating layers is the dominant
  idle cost. **Dense-map lite mode**: past `TEP_MAP_DENSE_N` (120) markers, the
  wrap gets `tep-agent-map-wrap--dense`, which drops the per-marker breathe
  animation AND its `will-change`. Small maps keep the liveliness.
- **Don't animate filters.** `filter: drop-shadow(...)` (a Gaussian blur) on an
  element that also animates (e.g. `stroke-dashoffset` on a trace line) forces a
  per-frame blur recompute over the element's whole bbox, ×N overlapping lines.
  The animated dash line has NO drop-shadow (the glow line beneath supplies the
  halo). Comets use a single blur, not stacked.
- **Trace lite mode**: past `TEP_TRACE_LITE_N` (20) concurrent trace lines, the
  flow SVG gets `tep-trace-lite`, which drops the marching-dash animation +
  comets but keeps the colored lines, loss rings, and latency tags.
- **Respect `prefers-reduced-motion`** — disable marching dashes/comets at any
  count.
- **Next lever (not yet done):** zoom-aware / screen-pixel clustering to cap the
  DOM node count at world zoom, then viewport culling (`display:none` off-screen
  markers). These attack the element *count*, which the lite-modes don't.
- General rule: at rest the map's cost is **CSS animations**, not JS —
  `layoutMarkers` only runs on zoom/pan. So perf work is mostly about reducing
  the number of continuously-animating/filtered elements.

## 9. Data windows, versioning, misc

- **`TEP_VERSION`** — a `const` near the top of `src/panel.js`; mirror the same
  number into `index.html`'s `install-version` span. `mirror.html` renders it live.
- **Data Window** — a shared time-window dropdown (`Past 1h`, etc.) driving the
  windowed SaaS/Network health + per-agent score fetches
  (`refreshDashMapColorScores`).
- **Toasts** — `tepMapToast(msg, 'ok'|'err')` for transient map feedback.
- **AID (account group)** — `teInitData._currentAid`; passed as
  `x-thousandeyes-aid` header / `aid` query param on TE requests and deep links.
- **Build script** — `scripts/build-min.js` (esbuild, whitespace-only). `npm run
  build` runs it. `package.json` has esbuild as the only devDep.
