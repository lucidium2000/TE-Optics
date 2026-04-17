/*
 * TE Optics — browser bookmarklet / panel for ThousandEyes (app.thousandeyes.com).
 *
 * Copyright (c) Christopher Hunt. All rights reserved.
 * Source & updates: https://github.com/lucidium2000/TE-Optics
 *
 * THIRD-PARTY MARKS / FAIR USE: “ThousandEyes”, Cisco product names, and related
 * marks are trademarks of Cisco Systems, Inc. This project is independent community
 * software; it is not sponsored, endorsed, or affiliated with Cisco or ThousandEyes.
 * References to those marks are for factual identification (nominative fair use).
 *
 * NO WARRANTY / NO SUPPORT: THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
 * EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY. You use this tool at your own risk, under your organization’s
 * policies and Cisco/ThousandEyes terms of service. This is not a supported product;
 * GitHub issues may be opened without any commitment to response time.
 */
(function () {
  'use strict';
  // If panel already exists, toggle visibility instead of creating a new one
  const existingRoot = document.getElementById('te-panel-root');
  const existingToggle = document.getElementById('tep-toggle-btn');
  if (existingRoot && existingToggle) {
    const isHidden = existingRoot.style.display === 'none';
    existingRoot.style.display = isHidden ? '' : 'none';
    const handle = document.getElementById('tep-resize-handle');
    if (handle) handle.style.display = isHidden ? '' : 'none';
    existingToggle.textContent = isHidden ? '✖' : '⚙️';
    return;
  }
  if (existingRoot) return;

  // ---------------------------------------------------------------------------
  // Dashboard route (/dashboard) — capture + helpers (no ajax() yet)
  // ---------------------------------------------------------------------------
  function isDashboardToolsPage() {
    try {
      const p = window.location.pathname || '';
      return p === '/dashboard' || p.startsWith('/dashboard/');
    } catch (_) {
      return false;
    }
  }

  const TEP_DASH_CAPTURE = { entries: [], max: 24 };
  /** @type {{ path: string, status: number, ct: string, snippet: string, t: number }[]} */
  const TEP_DASH_PROBE_HISTORY = [];
  /** @type {{ path: string, status: number, keys: string, t: number }[]} */
  const TEP_DASH_AJAX_SNIFF = [];
  /** Full JSON bodies from sniff that look like dashboards (URL may not say "dashboard"). */
  const TEP_DASH_SNIFF_BODIES = [];
  const TEP_DASH_PROBE_HISTORY_MAX = 40;
  const TEP_DASH_SNIFF_MAX = 80;
  const TEP_DASH_SNIFF_BODY_MAX = 16;
  const TEP_DASH_SNIFF_MIN_SCORE = 12;
  /** HTTP 200 on sniff-tracked paths where body did not parse as JSON (HTML, script, empty, etc.) */
  const TEP_DASH_NONJSON_200 = [];
  const TEP_DASH_NONJSON_MAX = 28;
  /** When set to current aid key, built-in GET probes all failed — skip re-fetching on every Refresh. */
  let dashProbeCacheFailAid = null;
  /** Avoid repeating the same "Sniff recorded N non-JSON…" panel line on every Refresh when N unchanged. */
  let dashNonJsonHintLastLoggedCount = -1;

  function dashConsole(level, msg, detail) {
    const fn = (console[level] || console.log).bind(console);
    try {
      if (detail !== undefined) fn('[TE Optics]', msg, detail);
      else fn('[TE Optics]', msg);
    } catch (_) { /* */ }
  }

  function pushProbeHistory(path, status, ct, snippet) {
    TEP_DASH_PROBE_HISTORY.unshift({
      path,
      status,
      ct: ct || '',
      snippet: (snippet || '').slice(0, 500),
      t: Date.now()
    });
    if (TEP_DASH_PROBE_HISTORY.length > TEP_DASH_PROBE_HISTORY_MAX) {
      TEP_DASH_PROBE_HISTORY.length = TEP_DASH_PROBE_HISTORY_MAX;
    }
  }

  function pushAjaxSniff(path, status, keysLabel) {
    TEP_DASH_AJAX_SNIFF.unshift({ path, status, keys: keysLabel, t: Date.now() });
    if (TEP_DASH_AJAX_SNIFF.length > TEP_DASH_SNIFF_MAX) TEP_DASH_AJAX_SNIFF.length = TEP_DASH_SNIFF_MAX;
  }

  function pathOnlyFromUrl(url) {
    if (!url || typeof url !== 'string') return '';
    try {
      if (url.startsWith('http')) return new URL(url).pathname + new URL(url).search;
    } catch (_) { /* */ }
    return url.split('#')[0];
  }

  /** TE sometimes returns JSON with text/html or missing Content-Type — parse only obvious JSON. */
  function tryParseJsonText(text) {
    try {
      const t = (text || '').replace(/^\uFEFF/, '').trim();
      if (!t || (t[0] !== '{' && t[0] !== '[')) return null;
      return JSON.parse(t);
    } catch (_) {
      return null;
    }
  }

  function isHtmlLikeResponse(text) {
    const t = (text || '').trim();
    return t.startsWith('<!') || /^<\s*html[\s>]/i.test(t);
  }

  function classifyNonJsonAjaxBody(text) {
    const t = (text || '').trim();
    if (!t.length) return 'empty';
    if (isHtmlLikeResponse(t)) return 'html';
    if (t[0] === '{' || t[0] === '[') return 'looks-like-json-parse-failed';
    return 'non-json-text';
  }

  function recordNonJsonAjax200(path, ct, bodyText, via) {
    const kind = classifyNonJsonAjaxBody(bodyText);
    const len = (bodyText || '').length;
    let head = '';
    if (kind === 'html') {
      head = (bodyText || '').replace(/\s+/g, ' ').slice(0, 100);
    } else if (kind === 'empty') {
      head = '(zero-length body)';
    } else {
      head = (bodyText || '').replace(/\s+/g, ' ').slice(0, 160);
    }
    TEP_DASH_NONJSON_200.unshift({
      path,
      ct: ct || '',
      len,
      kind,
      via,
      head,
      t: Date.now()
    });
    if (TEP_DASH_NONJSON_200.length > TEP_DASH_NONJSON_MAX) {
      TEP_DASH_NONJSON_200.length = TEP_DASH_NONJSON_MAX;
    }
  }

  /** One-line description for log (avoid dumping full XHTML 404 pages). */
  function summarizeProbeFailureSnippet(snippet, status) {
    const s = (snippet || '').trim();
    if (!s) return '(empty body)';
    if (isHtmlLikeResponse(s)) {
      return `HTTP ${status} HTML page (not a TE JSON API — built-in guess URL)`;
    }
    return s.slice(0, 160) + (s.length > 160 ? '…' : '');
  }

  function shouldCaptureDashboardUrl(url) {
    if (!url || typeof url !== 'string') return false;
    const lower = url.toLowerCase();
    if (!lower.includes('thousandeyes.com') && !lower.startsWith('/')) return false;
    let path = lower;
    try {
      if (lower.startsWith('http')) path = new URL(url).pathname.toLowerCase();
      else path = lower.split('?')[0].split('#')[0];
    } catch (_) { /* keep path */ }
    if (path.includes('/namespace/dash-api')) return true;
    if (!path.includes('/ajax/')) return false;
    return path.includes('dashboard');
  }

  /**
   * Fetch/XHR hook logs dashboard-ish URLs. 404s are often expected (wrong probe guess, id not in account);
   * 400 usually means TE rejected the request body (restore/update validation).
   */
  function logDashboardHookNonOk(via, pathKey, status, ct, bodySlice) {
    const detail = {
      path: pathKey,
      status,
      ct: ct || '',
      body: (bodySlice || '').slice(0, 400)
    };
    if (status === 404) {
      detail.why = 'Nothing at this URL for your session — common for guessed /ajax/dashboard/* probes, wrong dashboard id for this aid, or a GET shape TE does not use (try the other tab Network request that returns 200 JSON).';
      dashConsole('info', `dashboard-ish URL ${via} → 404`, detail);
      return;
    }
    if (status === 400) {
      detail.why = 'Server refused the request — for POST /namespace/dash-api/dashboard, read `body` for TE\'s message (invalid widget JSON, id in body on create, duplicate name, etc.). GET with only ?dashboardId= can also 400 if TE expects a different method or path.';
      dashConsole('warn', `dashboard-ish URL ${via} → 400`, detail);
      return;
    }
    detail.why = 'Non-success response on a dashboard-related URL.';
    dashConsole('warn', `dashboard-ish URL ${via} non-OK`, detail);
  }

  /** Same-origin paths where sniff logs JSON / non-JSON-200 like DevTools (not only /ajax/). */
  function isSniffableDashboardNetworkPath(pathKey) {
    const p = (pathKey || '').toLowerCase();
    return p.includes('/ajax/') || p.includes('/namespace/dash-api');
  }

  function scoreDashboardPayload(obj, depth) {
    if (depth == null) depth = 0;
    if (depth > 2) return -1;
    if (!obj || typeof obj !== 'object') return -1;
    if (Array.isArray(obj)) return obj.length ? 4 : -1;
    let s = 0;
    if (Array.isArray(obj.widgets)) s += 60 + Math.min(obj.widgets.length * 2, 40);
    if (obj.template && typeof obj.template === 'object' && Array.isArray(obj.template.widgets)) {
      s += 60 + Math.min(obj.template.widgets.length * 2, 40);
    }
    if (obj.dashboard && typeof obj.dashboard === 'object') s += 45;
    if (typeof obj.title === 'string' && obj.title.length) s += 8;
    if (typeof obj.dashboardTitle === 'string') s += 8;
    if (obj.dashboardId != null || obj.id != null) s += 12;
    if (Array.isArray(obj.dashboards)) s += 25;
    if (typeof obj.layout === 'object' && obj.layout) s += 15;
    if (Array.isArray(obj.items) && obj.items.length && (obj.layout || obj.grid || obj.gridLayout)) s += 28;
    if (obj.gridLayout && typeof obj.gridLayout === 'object') s += 22;
    if (Array.isArray(obj.panels) && obj.panels.length) s += 20;
    if (Array.isArray(obj.tiles) && obj.tiles.length) s += 18;
    for (const wrap of ['data', 'payload', 'result']) {
      const inner = obj[wrap];
      if (inner && typeof inner === 'object') {
        const innerScore = scoreDashboardPayload(inner, depth + 1);
        if (innerScore > s) s = innerScore;
      }
    }
    return s;
  }

  /**
   * POST /namespace/dash-api/poll often returns { status: 'NOCHANGE', dashboard: null } — valid JSON but not a backup.
   * Full dashboard definitions usually come from another request (sniff Network for large JSON with widgets/layout).
   */
  function isNamespacePollMissingDashboardDoc(data) {
    if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
    if (data.dashboard != null && typeof data.dashboard === 'object') return false;
    return scoreDashboardPayload(data) < TEP_DASH_SNIFF_MIN_SCORE;
  }

  function maybeRecordSniffDashboardBody(path, data, via) {
    const score = scoreDashboardPayload(data);
    if (score < TEP_DASH_SNIFF_MIN_SCORE) return;
    TEP_DASH_SNIFF_BODIES.unshift({
      path,
      data,
      score,
      t: Date.now(),
      via
    });
    if (TEP_DASH_SNIFF_BODIES.length > TEP_DASH_SNIFF_BODY_MAX) {
      TEP_DASH_SNIFF_BODIES.length = TEP_DASH_SNIFF_BODY_MAX;
    }
    dashConsole('info', 'sniff stored dashboard-like JSON', { path, score, via, keys: topLevelKeysLabel(data) });
  }

  function topLevelKeysLabel(data) {
    try {
      if (data == null) return String(data);
      if (Array.isArray(data)) return `Array(len=${data.length})`;
      if (typeof data === 'object') return '{' + Object.keys(data).slice(0, 20).join(', ') + (Object.keys(data).length > 20 ? ', …' : '') + '}';
      return String(data).slice(0, 80);
    } catch (_) {
      return '?';
    }
  }

  function recordDashboardSnapshot(url, data) {
    const score = scoreDashboardPayload(data);
    if (score < 0) return;
    TEP_DASH_CAPTURE.entries.unshift({ url, data, score, t: Date.now() });
    TEP_DASH_CAPTURE.entries = TEP_DASH_CAPTURE.entries.slice(0, TEP_DASH_CAPTURE.max);
    dashConsole('info', 'dashboard capture stored', {
      path: pathOnlyFromUrl(url),
      score,
      keys: topLevelKeysLabel(data)
    });
  }

  /**
   * Best payload from URL-keyword captures OR sniffed high-scoring JSON (any /ajax path).
   * When focusDashboardId is set (from the page URL), only entries that match that id are used
   * so switching dashboards does not resurrect a stale capture from another id.
   */
  function pickBestDashboardLikePayload(focusDashboardId) {
    let best = null;
    for (const e of TEP_DASH_CAPTURE.entries) {
      if (focusDashboardId && !snapshotMatchesFocusDashboardId(e.url, e.data, focusDashboardId)) continue;
      let data = e.data;
      let score = e.score;
      if (focusDashboardId) {
        const narrowed = selectDashboardForFocusFromAggregate(e.data, focusDashboardId);
        if (narrowed) {
          data = narrowed;
          score = scoreDashboardPayload(narrowed);
        }
      }
      const cand = { path: pathOnlyFromUrl(e.url), data, score, source: 'capture (URL has "dashboard")' };
      if (!best || cand.score > best.score) best = cand;
    }
    for (const e of TEP_DASH_SNIFF_BODIES) {
      if (focusDashboardId && !snapshotMatchesFocusDashboardId(e.path, e.data, focusDashboardId)) continue;
      let data = e.data;
      let score = e.score;
      if (focusDashboardId) {
        const narrowed = selectDashboardForFocusFromAggregate(e.data, focusDashboardId);
        if (narrowed) {
          data = narrowed;
          score = scoreDashboardPayload(narrowed);
        }
      }
      const cand = { path: e.path, data, score, source: `sniff (${e.via})` };
      if (!best || cand.score > best.score) best = cand;
    }
    return best;
  }

  /** TE dashboard ids are often 24-char hex ObjectIds in ?dashboardId= (not only numeric). */
  function looksLikeTeDashboardId(s) {
    if (!s || typeof s !== 'string') return false;
    const t = s.trim();
    if (/^\d+$/.test(t)) return true;
    if (/^[a-f0-9]{24}$/i.test(t)) return true;
    if (/^[a-z0-9-]{8,64}$/i.test(t)) return true;
    return false;
  }

  function extractDashboardIdFromLocation() {
    try {
      const q = new URLSearchParams(window.location.search || '');
      for (const key of ['dashboardId', 'dashboard', 'did', 'id']) {
        const v = q.get(key);
        if (v && looksLikeTeDashboardId(v)) return v.trim();
      }
      const m = (window.location.pathname || '').match(/\/dashboards?\/([a-z0-9-]{8,64})/i);
      if (m && looksLikeTeDashboardId(m[1])) return m[1];
      const hash = window.location.hash || '';
      const m2 = hash.match(/(?:dashboard|boards)\/([a-z0-9-]{8,64})/i);
      if (m2 && looksLikeTeDashboardId(m2[1])) return m2[1];
    } catch (_) { /* */ }
    return null;
  }

  /** Parse dashboard id from a captured request path or full URL (query or /dashboards/:id segment). */
  function extractDashboardIdFromRequestPath(pathOrUrl) {
    if (!pathOrUrl || typeof pathOrUrl !== 'string') return null;
    try {
      const u = pathOrUrl.includes('//')
        ? new URL(pathOrUrl)
        : new URL(pathOrUrl.startsWith('/') ? `http://local.invalid${pathOrUrl}` : `http://local.invalid/${pathOrUrl}`);
      for (const key of ['dashboardId', 'dashboard', 'did', 'id']) {
        const v = u.searchParams.get(key);
        if (v && looksLikeTeDashboardId(v)) return v.trim();
      }
    } catch (_) { /* */ }
    const pathOnly = (pathOrUrl.split('?')[0] || '').split('#')[0];
    const nsSeg = pathOnly.match(/\/namespace\/dash-api\/dashboard\/([^/?#]+)/i);
    if (nsSeg) {
      const seg = decodeURIComponent(nsSeg[1]);
      if (looksLikeTeDashboardId(seg)) return seg.trim();
    }
    const m = pathOnly.match(/\/dashboards?\/([a-z0-9-]{8,64})/i);
    if (m && looksLikeTeDashboardId(m[1])) return m[1];
    return null;
  }

  function getPayloadDashboardId(data) {
    if (data == null) return null;
    let v = unwrapIfSingleElementArray(data);
    if (Array.isArray(v)) {
      const picked = pickDashboardFromArray(v);
      if (picked) return getPayloadDashboardId(picked);
      return null;
    }
    if (!v || typeof v !== 'object') return null;
    const read = (o) => {
      if (!o || typeof o !== 'object') return null;
      for (const k of ['dashboardId', 'dashboard_id', 'id', '_id', 'mongoId']) {
        if (o[k] != null) {
          const s = String(o[k]).trim();
          if (s) return s;
        }
      }
      return null;
    };
    let id = read(v);
    if (id) return id;
    if (v.dashboard && typeof v.dashboard === 'object') {
      id = read(v.dashboard);
      if (id) return id;
    }
    if (v.data != null && typeof v.data === 'object') return getPayloadDashboardId(v.data);
    if (v.result != null && typeof v.result === 'object') return getPayloadDashboardId(v.result);
    return null;
  }

  function dashboardEntryMatchesFocus(entry, focusId) {
    if (!entry || typeof entry !== 'object' || !focusId) return false;
    const id = String(focusId);
    const pid = getPayloadDashboardId(entry);
    if (pid && String(pid) === id) return true;
    for (const k of ['connectionName', 'connectionId', 'slug']) {
      if (entry[k] != null && String(entry[k]).trim() === id) return true;
    }
    if (entry.dashboard && typeof entry.dashboard === 'object') {
      const inner = getPayloadDashboardId(entry.dashboard);
      if (inner && String(inner) === id) return true;
    }
    return false;
  }

  /**
   * TE often returns a list or wrapper (all dashboards) from GET /namespace/dash-api/dashboard.
   * Pick the one row/document that matches the dashboard id in the URL (id fields, connectionName, etc.).
   */
  function selectDashboardForFocusFromAggregate(data, focusId) {
    if (!focusId || data == null) return null;
    let v = unwrapIfSingleElementArray(data);
    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        const el = v[i];
        if (el && typeof el === 'object' && dashboardEntryMatchesFocus(el, focusId)) return el;
      }
      return null;
    }
    if (typeof v === 'object' && v !== null) {
      if (v.dashboard && typeof v.dashboard === 'object' && !Array.isArray(v.dashboard)) {
        if (dashboardEntryMatchesFocus(v.dashboard, focusId)) return v.dashboard;
        const one = selectDashboardForFocusFromAggregate(v.dashboard, focusId);
        if (one) return one;
      }
      for (const key of ['dashboards', 'items', 'results', 'content', 'records', 'connections', 'data']) {
        const inner = v[key];
        if (Array.isArray(inner)) {
          for (let j = 0; j < inner.length; j++) {
            const el = inner[j];
            if (el && typeof el === 'object' && dashboardEntryMatchesFocus(el, focusId)) return el;
          }
        } else if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
          const sub = selectDashboardForFocusFromAggregate(inner, focusId);
          if (sub) return sub;
        }
      }
      if (dashboardEntryMatchesFocus(v, focusId)) return v;
    }
    return null;
  }

  function snapshotMatchesFocusDashboardId(entryUrlOrPath, payload, focusId) {
    if (!focusId) return true;
    const p = pathOnlyFromUrl(entryUrlOrPath || '') || (entryUrlOrPath || '');
    const fromReq = extractDashboardIdFromRequestPath(p) || extractDashboardIdFromRequestPath(entryUrlOrPath || '');
    if (fromReq && String(fromReq) === String(focusId)) return true;
    const fromBody = getPayloadDashboardId(payload);
    if (fromBody && String(fromBody) === String(focusId)) return true;
    if (selectDashboardForFocusFromAggregate(payload, focusId)) return true;
    return false;
  }

  function installDashboardNetworkCapture() {
    if (!isDashboardToolsPage()) return;
    if (window.__TEP_OPTICS_DASH_CAPTURE__) return;
    window.__TEP_OPTICS_DASH_CAPTURE__ = true;

    const origFetch = window.fetch.bind(window);
    window.fetch = async function (...args) {
      const res = await origFetch(...args);
      try {
        let reqUrl = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url);
        if (args[0] instanceof Request) reqUrl = args[0].url;
        const pathKey = pathOnlyFromUrl(reqUrl || '');
        const sniffOn = window.__TEP_OPTICS_SNIFF_AJAX__ !== false;

        if (reqUrl && shouldCaptureDashboardUrl(reqUrl)) {
          const clone = res.clone();
          const ct = (clone.headers && clone.headers.get && clone.headers.get('content-type')) || '';
          const bodyText = await clone.text();
          const parsed = tryParseJsonText(bodyText);
          if (clone.ok && parsed != null) {
            recordDashboardSnapshot(reqUrl, parsed);
          } else if (clone.ok) {
            dashConsole('info', 'dashboard-ish URL OK but body not JSON', {
              path: pathKey,
              ct,
              preview: bodyText.slice(0, 120)
            });
          } else {
            logDashboardHookNonOk('fetch', pathKey, clone.status, ct, bodyText);
          }
        } else if (sniffOn && isSniffableDashboardNetworkPath(pathKey)) {
          const clone = res.clone();
          if (clone.ok) {
            const bodyText = await clone.text();
            const data = tryParseJsonText(bodyText);
            if (data != null) {
              pushAjaxSniff(pathKey, res.status, topLevelKeysLabel(data));
              maybeRecordSniffDashboardBody(pathKey, data, 'fetch');
              dashConsole('info', 'ajax JSON (fetch)', { path: pathKey, status: res.status, keys: topLevelKeysLabel(data) });
            } else {
              const ct2 = (clone.headers && clone.headers.get && clone.headers.get('content-type')) || '';
              recordNonJsonAjax200(pathKey, ct2, bodyText, 'fetch');
            }
          }
        }
      } catch (e) {
        dashConsole('warn', 'fetch hook parse error', e && e.message ? e.message : String(e));
      }
      return res;
    };

    const XHROpen = XMLHttpRequest.prototype.open;
    const XHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url, ...rest) {
      try { this.__tep_req_url = typeof url === 'string' ? url : String(url); } catch (_) { this.__tep_req_url = ''; }
      return XHROpen.call(this, method, url, ...rest);
    };
    XMLHttpRequest.prototype.send = function (body) {
      this.addEventListener('load', function () {
        try {
          const reqUrl = this.__tep_req_url || '';
          const pathKey = pathOnlyFromUrl(reqUrl);
          const sniffOn = window.__TEP_OPTICS_SNIFF_AJAX__ !== false;
          const ct = this.getResponseHeader('content-type') || '';
          const st = this.status;
          if (shouldCaptureDashboardUrl(reqUrl)) {
            const raw = String(this.responseText || '');
            const parsed = tryParseJsonText(raw);
            if (st >= 200 && st < 300 && parsed != null) {
              recordDashboardSnapshot(reqUrl, parsed);
            } else if (st >= 200 && st < 300) {
              dashConsole('info', 'XHR dashboard-ish OK but body not JSON', {
                path: pathKey,
                ct,
                preview: raw.slice(0, 120)
              });
            } else {
              logDashboardHookNonOk('xhr', pathKey, st, ct, raw);
            }
            return;
          }
          if (sniffOn && isSniffableDashboardNetworkPath(pathKey) && st >= 200 && st < 300) {
            const raw = String(this.responseText || '');
            const data = tryParseJsonText(raw);
            if (data != null) {
              pushAjaxSniff(pathKey, st, topLevelKeysLabel(data));
              maybeRecordSniffDashboardBody(pathKey, data, 'xhr');
              dashConsole('info', 'ajax JSON (XHR)', { path: pathKey, status: st, keys: topLevelKeysLabel(data) });
            } else {
              recordNonJsonAjax200(pathKey, ct, raw, 'xhr');
            }
          }
        } catch (e) {
          dashConsole('warn', 'XHR hook error', e && e.message ? e.message : String(e));
        }
      });
      return XHRSend.call(this, body);
    };
    dashConsole('info', 'TE Optics: dashboard hooks active — open DevTools Console and filter for "[TE Optics]"', {
      sniffAllAjaxJson: window.__TEP_OPTICS_SNIFF_AJAX__ !== false,
      hint: 'Use "Copy troubleshooting report" in the panel after loading a backup to capture probe + sniff history.'
    });
  }

  installDashboardNetworkCapture();

  // ---------------------------------------------------------------------------
  // Config — uses TE's internal /ajax/ API (same-origin, session cookies)
  // ---------------------------------------------------------------------------
  let csrfToken = null;
  let teInitData = null;  // response from /ajax/settings/tests/init

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------
  let agents = [];
  let accountGroups = [];
  let selectedAgentIds = new Set();
  /** Latest rows from “Dashboard cleanup” list fetch ({ id, title, modifiedMs }). */
  let dashCleanupCatalog = [];
  let dashCleanupListEverLoaded = false;
  /** When true, higher `modifiedMs` appears first; when false, oldest first. */
  let dashCleanupSortNewestFirst = true;

  // ---------------------------------------------------------------------------
  // Styles (scoped via #te-panel-root)
  // ---------------------------------------------------------------------------
  const STYLES = `
    #te-panel-root {
      position: fixed; top: 0; right: 0; z-index: 2147483647;
      width: var(--tep-width, 576px); height: 100vh;
      background: #0f172a; color: #e2e8f0;
      border-left: 1px solid #334155;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 13px; box-shadow: -4px 0 20px rgba(0,0,0,.4);
      display: flex; flex-direction: column; overflow: hidden;
    }
    #te-panel-root * { box-sizing: border-box; }

    /* Resize gutter */
    #tep-resize-handle {
      position: fixed; top: 0; width: 6px; height: 100vh;
      cursor: col-resize; z-index: 2147483648;
      background: transparent;
    }
    #tep-resize-handle:hover, #tep-resize-handle.active {
      background: #3b82f6;
    }

    /* Header */
    .tep-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 16px; background: #1e293b; border-bottom: 1px solid #334155;
      user-select: none; gap: 8px;
    }
    .tep-header h2 { font-size: 15px; font-weight: 700; color: #f1f5f9; margin: 0; flex: 1; }
    .tep-dark-toggle {
      background: none; border: 1px solid #475569; color: #94a3b8; font-size: 16px;
      cursor: pointer; padding: 2px 6px; border-radius: 6px; line-height: 1;
    }
    .tep-dark-toggle:hover { color: #f1f5f9; border-color: #64748b; }
    .tep-dark-toggle.active { color: #facc15; border-color: #facc15; }
    .tep-close {
      background: none; border: none; color: #94a3b8; font-size: 20px;
      cursor: pointer; line-height: 1; padding: 0 4px;
    }
    .tep-close:hover { color: #f87171; }

    /* Body */
    .tep-body { padding: 16px; overflow-y: auto; flex: 1; }

    /* Status bar */
    .tep-status {
      padding: 8px 12px; font-size: 12px; color: #94a3b8;
      background: #1e293b; border-bottom: 1px solid #334155;
    }
    .tep-status.ok { color: #4ade80; }
    .tep-status.err { color: #f87171; }

    /* Toast notifications */
    .tep-toast {
      padding: 8px 14px; font-size: 12px; font-weight: 600;
      border-radius: 6px; margin: 6px 16px 0; animation: tepFadeIn .2s;
    }
    .tep-toast-ok { background: #064e3b; color: #4ade80; border: 1px solid #065f46; }
    .tep-toast-err { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .tep-toast-processing { background: #1e293b; color: #38bdf8; border: 1px solid #0ea5e9; animation: tepFadeIn .2s, tepPulse 1.5s ease-in-out infinite; }
    @keyframes tepFadeIn { from { opacity: 0; transform: translateY(-6px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes tepPulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }

    /* Form elements */
    .tep-label {
      display: block; font-size: 12px; font-weight: 600; color: #94a3b8;
      margin-bottom: 4px; margin-top: 12px;
    }
    .tep-label:first-child { margin-top: 0; }
    .tep-input, .tep-select, .tep-textarea {
      width: 100%; padding: 10px 10px; background: #1e293b;
      border: 1px solid #334155; border-radius: 6px; color: #e2e8f0;
      font-size: 13px; outline: none; transition: border-color .15s;
    }
    .tep-input:focus, .tep-select:focus, .tep-textarea:focus {
      border-color: #3b82f6;
    }
    .tep-textarea { resize: vertical; min-height: 70px; font-family: monospace; }
    .tep-targets-wrap {
      display: flex;
      gap: 4px;
      align-items: stretch;
    }
    .tep-targets-wrap .tep-textarea {
      flex: 1;
      min-width: 0;
      width: auto !important;
    }
    .tep-targets-gutter {
      flex-shrink: 0;
      display: flex;
      flex-direction: column;
      padding-top: 10px;
      padding-bottom: 10px;
      user-select: none;
    }
    .tep-targets-gutter-row {
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }
    button.tep-target-clone-line {
      border: none;
      background: transparent;
      color: #64748b;
      cursor: pointer;
      font-size: 14px;
      font-weight: 600;
      line-height: 1;
      width: 22px;
      height: 22px;
      margin: 0;
      padding: 0;
      border-radius: 4px;
    }
    button.tep-target-clone-line:hover {
      color: #38bdf8;
      background: #1e3a5f;
    }
    .tep-input { height: 38px; }
    .tep-select { appearance: auto; height: 38px; line-height: 18px; }

    /* Agent list */
    .tep-agents-box {
      max-height: 180px; overflow-y: auto; background: #1e293b;
      border: 1px solid #334155; border-radius: 6px; padding: 6px;
      margin-top: 4px;
    }
    .tep-agent-item {
      display: flex; align-items: center; gap: 6px;
      padding: 4px 6px; border-radius: 4px; cursor: pointer;
    }
    .tep-agent-item:hover { background: #334155; }
    .tep-agent-item input { accent-color: #3b82f6; }
    .tep-agent-name { color: #e2e8f0; font-size: 12px; }
    .tep-agent-loc { color: #64748b; font-size: 11px; }
    .tep-agent-status { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 2px; flex-shrink: 0; }
    .tep-agent-status.online { background: #4ade80; box-shadow: 0 0 4px #4ade80; }
    .tep-agent-status.offline { background: #f87171; box-shadow: 0 0 4px #f87171; }
    .tep-agent-status.unknown { background: #64748b; }

    /* Filter */
    .tep-agent-filter-wrap {
      position: relative;
      margin-bottom: 6px;
    }
    .tep-agent-filter-wrap--compact {
      margin-bottom: 4px;
      margin-top: 4px;
    }
    .tep-agent-filter-wrap .tep-agent-filter,
    .tep-agent-filter-wrap .tep-edit-agent-filter {
      width: 100%;
      margin-bottom: 0;
      padding-right: 30px;
      box-sizing: border-box;
    }
    .tep-agent-filter {
      padding: 6px 8px; background: #0f172a;
      border: 1px solid #334155; border-radius: 4px; color: #e2e8f0;
      font-size: 12px; outline: none;
    }
    .tep-agent-filter:focus { border-color: #3b82f6; }
    .tep-agent-filter-clear {
      position: absolute;
      right: 5px;
      top: 50%;
      transform: translateY(-50%);
      width: 22px;
      height: 22px;
      border: none;
      border-radius: 4px;
      background: #334155;
      color: #94a3b8;
      font-size: 15px;
      line-height: 1;
      cursor: pointer;
      padding: 0;
      display: none;
      align-items: center;
      justify-content: center;
    }
    .tep-agent-filter-clear:hover {
      color: #e2e8f0;
      background: #475569;
    }

    /* Buttons */
    .tep-btn {
      display: inline-flex; align-items: center; justify-content: center;
      padding: 9px 18px; border: none; border-radius: 7px;
      font-size: 13px; font-weight: 600; cursor: pointer;
      transition: background .15s, transform .1s;
    }
    .tep-btn:active { transform: scale(0.97); }
    .tep-btn-primary { background: #3b82f6; color: #fff; }
    .tep-btn-primary:hover { background: #2563eb; }
    .tep-btn-primary:disabled { background: #1e40af; opacity: 0.5; cursor: not-allowed; }
    .tep-btn-secondary { background: #334155; color: #e2e8f0; }
    .tep-btn-secondary:hover { background: #475569; }
    .tep-btn-danger { background: #450a0a; color: #f87171; border: 1px solid #7f1d1d; }
    .tep-btn-danger:hover { background: #7f1d1d; color: #fecaca; }
    .tep-btn-sm { padding: 5px 10px; font-size: 12px; }
    .tep-dash-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; align-items: center; }
    .tep-dash-intro { font-size: 12px; color: #94a3b8; line-height: 1.55; margin: 0 0 14px; }
    .tep-dash-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 12px 14px 14px;
      margin-bottom: 12px;
    }
    .tep-dash-section-title { font-size: 13px; font-weight: 700; color: #f1f5f9; margin: 0 0 6px; }
    .tep-dash-hint { font-size: 11px; color: #64748b; line-height: 1.45; margin: 0 0 10px; }
    .tep-dash-meta {
      font-size: 11px; color: #94a3b8; margin-bottom: 10px; line-height: 1.5;
      padding: 8px 10px; background: #0f172a; border-radius: 6px; border: 1px solid #1e293b;
    }
    .tep-dash-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: stretch; margin-top: 8px; }
    .tep-dash-row .tep-btn-primary { flex: 1 1 160px; }
    .tep-dash-json { min-height: 200px; font-size: 11px; }
    .tep-dash-json-details {
      margin-top: 8px; border: 1px solid #334155; border-radius: 8px; background: #0f172a; overflow: hidden;
    }
    .tep-dash-json-details > summary {
      list-style: none; cursor: pointer; padding: 10px 12px; font-size: 12px; user-select: none;
      display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; color: #cbd5e1;
    }
    .tep-dash-json-details > summary::-webkit-details-marker { display: none; }
    .tep-dash-json-details[open] > summary { border-bottom: 1px solid #334155; color: #f1f5f9; }
    .tep-dash-json-details > summary .tep-dash-json-sum { flex: 1; min-width: 0; font-weight: 600; line-height: 1.45; word-break: break-word; }
    .tep-dash-json-details > summary .tep-dash-json-chev { flex-shrink: 0; font-size: 10px; color: #64748b; margin-top: 3px; transition: transform .15s; }
    .tep-dash-json-details[open] > summary .tep-dash-json-chev { transform: rotate(90deg); }
    .tep-dash-json-sum-ok { color: #86efac !important; }
    .tep-dash-json-sum-err { color: #f87171 !important; }
    .tep-dash-json-sum-empty { color: #94a3b8 !important; font-weight: 500 !important; }
    .tep-dash-json-details-body { padding: 10px 12px 12px; }
    .tep-dash-restore-bar { margin-top: 12px; padding-top: 12px; border-top: 1px solid #334155; }
    .tep-dash-details {
      margin-top: 4px; border: 1px solid #334155; border-radius: 8px; background: #0f172a; overflow: hidden;
    }
    .tep-dash-details > summary {
      list-style: none; cursor: pointer; padding: 10px 12px; font-size: 12px; font-weight: 600;
      color: #94a3b8; user-select: none; display: flex; align-items: center; justify-content: space-between; gap: 8px;
    }
    .tep-dash-details > summary::-webkit-details-marker { display: none; }
    .tep-dash-details > summary .tep-dash-chevron { font-size: 10px; color: #64748b; transition: transform .15s; }
    .tep-dash-details[open] > summary .tep-dash-chevron { transform: rotate(90deg); }
    .tep-dash-details[open] > summary { border-bottom: 1px solid #334155; color: #e2e8f0; }
    .tep-dash-details-inner { padding: 12px 14px 14px; font-size: 11px; color: #94a3b8; line-height: 1.5; }
    .tep-dash-details-inner code { font-size: 10px; }
    .tep-dash-restore-card .tep-label { margin-top: 10px; }
    .tep-dash-restore-card .tep-label:first-of-type { margin-top: 0; }
    .tep-dash-restore-agents-wrap {
      margin-top: 10px; padding: 10px; background: #0f172a; border-radius: 8px; border: 1px solid #334155;
    }
    .tep-dash-cleanup {
      margin-top: 22px;
      padding-top: 20px;
      border-top: 2px solid #475569;
    }
    .tep-dash-cleanup-meta { font-size: 11px; color: #94a3b8; margin: 0 0 8px; line-height: 1.45; }
    .tep-dash-cleanup-toolbar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 8px; }
    .tep-dash-cleanup-list {
      max-height: 240px; overflow-y: auto; margin-top: 8px; border: 1px solid #334155; border-radius: 8px;
      background: #0f172a;
    }
    .tep-dash-cleanup-row { padding: 8px 10px; border-bottom: 1px solid #1e293b; font-size: 12px; }
    .tep-dash-cleanup-row:last-child { border-bottom: none; }
    .tep-dash-cleanup-row label { display: flex; gap: 8px; align-items: flex-start; cursor: pointer; width: 100%; }
    .tep-dash-cleanup-row .tep-dash-cleanup-cb { margin-top: 2px; flex-shrink: 0; accent-color: #3b82f6; }
    .tep-dash-cleanup-titles { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
    .tep-dash-cleanup-name { font-weight: 600; color: #e2e8f0; word-break: break-word; }
    .tep-dash-cleanup-id { font-size: 10px; color: #64748b; word-break: break-all; }
    .tep-dash-tab-panel { display: none; }
    .tep-dash-tab-panel.active { display: block; }
    .tep-actions { display: flex; gap: 8px; margin-top: 16px; }

    .tep-attribution {
      margin-top: 12px;
      padding: 8px 10px;
      border: 1px solid #334155;
      border-radius: 8px;
      background: #0f172a;
      font-size: 10px;
      line-height: 1.45;
      color: #94a3b8;
    }
    .tep-attribution a {
      color: #93c5fd;
      text-decoration: underline;
      text-underline-offset: 2px;
    }
    .tep-attribution a:hover { color: #bfdbfe; }

    /* Results log */
    .tep-log-wrap {
      margin-top: 14px;
    }
    .tep-log-toolbar {
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 0;
    }
    .tep-log-toolbar .tep-log-toggle {
      flex: 1;
      min-width: 0;
      width: auto;
    }
    .tep-log-copy {
      flex-shrink: 0;
      background: #334155;
      border: 1px solid #475569;
      color: #e2e8f0;
      font-size: 11px;
      font-weight: 600;
      padding: 5px 12px;
      border-radius: 6px;
      cursor: pointer;
      white-space: nowrap;
    }
    .tep-log-copy:hover { background: #475569; color: #f8fafc; }
    .tep-log-toggle {
      background: #1e293b; border: 1px solid #334155; border-radius: 6px;
      color: #94a3b8; font-size: 11px; font-weight: 600; padding: 5px 10px;
      cursor: pointer; width: 100%; text-align: left;
      display: flex; align-items: center; gap: 6px;
    }
    .tep-log-toggle:hover { background: #334155; color: #e2e8f0; }
    .tep-log-toggle .tep-log-arrow { transition: transform .15s; display: inline-block; }
    .tep-log-toggle.open .tep-log-arrow { transform: rotate(90deg); }
    .tep-log {
      background: #020617; border: 1px solid #1e293b;
      border-radius: 0 0 6px 6px; padding: 10px; font-family: monospace; font-size: 11px;
      max-height: 200px; overflow-y: auto; white-space: pre-wrap;
      line-height: 1.6; display: none;
    }
    .tep-log.open { display: block; }
    .tep-log-ok { color: #4ade80; }
    .tep-log-err { color: #f87171; }
    .tep-log-info { color: #94a3b8; }

    /* Tabs */
    .tep-tabs { display: flex; gap: 2px; margin-bottom: 14px; }
    .tep-tab {
      flex: 1; padding: 7px 4px; text-align: center; font-size: 12px;
      font-weight: 600; background: #1e293b; border: 1px solid #334155;
      color: #94a3b8; cursor: pointer; border-radius: 6px;
      transition: background .15s, color .15s;
    }
    .tep-tab:hover { background: #334155; color: #e2e8f0; }
    .tep-tab.active { background: #3b82f6; color: #fff; border-color: #3b82f6; }

    /* Section toggles */
    .tep-section-title {
      font-size: 13px; font-weight: 700; color: #cbd5e1;
      margin-top: 16px; margin-bottom: 8px;
      padding-bottom: 4px; border-bottom: 1px solid #1e293b;
    }

    /* Top-level view switcher */
    .tep-view-tabs { display: flex; border-bottom: 1px solid #334155; }
    .tep-view-tab {
      flex: 1; padding: 10px; text-align: center; font-size: 13px;
      font-weight: 600; color: #94a3b8; cursor: pointer;
      background: #1e293b; border: none; transition: all .15s;
    }
    .tep-view-tab:hover { color: #e2e8f0; background: #273449; }
    .tep-view-tab.active { color: #3b82f6; border-bottom: 2px solid #3b82f6; background: #0f172a; }
    .tep-view-panel { display: none; }
    .tep-view-panel.active { display: block; }

    /* Test cards */
    .tep-test-card {
      background: #1e293b; border: 1px solid #334155; border-radius: 8px;
      padding: 10px 12px; margin-bottom: 8px; transition: border-color .15s;
    }
    .tep-test-card:hover { border-color: #475569; }
    .tep-test-card-header { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
    .tep-test-card-name { font-weight: 600; color: #e2e8f0; font-size: 13px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-flex; align-items: center; gap: 4px; }
    .tep-test-link { font-size: 11px; text-decoration: none; opacity: 0.35; transition: opacity .15s; flex-shrink: 0; }
    .tep-test-link:hover { opacity: 1; }
    .tep-test-card-meta { display: flex; gap: 8px; margin-top: 6px; font-size: 11px; color: #64748b; flex-wrap: wrap; }
    .tep-test-card-meta span { display: inline-flex; align-items: center; gap: 3px; }
    .tep-type-badge {
      font-size: 10px; font-weight: 700; padding: 2px 6px; border-radius: 4px;
      text-transform: uppercase; letter-spacing: .5px; white-space: nowrap;
    }
    .tep-type-http { background: #1e3a5f; color: #60a5fa; }
    .tep-type-a2s { background: #1a3f2e; color: #4ade80; }
    .tep-type-page { background: #3b1f5e; color: #c084fc; }
    .tep-type-dns { background: #3b3510; color: #facc15; }
    .tep-type-other { background: #334155; color: #94a3b8; }
    .tep-test-actions { display: flex; gap: 4px; }
    .tep-test-actions button {
      background: #334155; border: 1px solid #475569; color: #94a3b8;
      font-size: 11px; padding: 3px 8px; border-radius: 4px; cursor: pointer;
      transition: all .15s;
    }
    .tep-test-actions button:hover { background: #475569; color: #e2e8f0; }
    .tep-test-actions button.tep-btn-danger:hover { background: #7f1d1d; color: #fca5a5; border-color: #991b1b; }
    .tep-enabled-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
    .tep-enabled-dot.on { background: #4ade80; }
    .tep-enabled-dot.off { background: #f87171; }
    .tep-manage-toolbar { display: flex; gap: 8px; margin-bottom: 12px; align-items: center; flex-wrap: wrap; }
    .tep-manage-toolbar select, .tep-manage-toolbar input {
      padding: 6px 8px; background: #1e293b; border: 1px solid #334155;
      border-radius: 6px; color: #e2e8f0; font-size: 12px; outline: none;
    }
    .tep-manage-toolbar input { flex: 1; min-width: 120px; }
    .tep-manage-toolbar select { min-width: 100px; }
    .tep-test-list { max-height: calc(100vh - 340px); overflow-y: auto; }
    .tep-test-count { font-size: 11px; color: #64748b; margin-bottom: 8px; }

    /* Edit form inline */
    .tep-edit-form { margin-top: 8px; padding-top: 8px; border-top: 1px solid #334155; }
    .tep-edit-row { display: flex; gap: 8px; margin-bottom: 6px; align-items: center; }
    .tep-edit-row label { font-size: 11px; color: #94a3b8; min-width: 60px; }
    .tep-edit-row input, .tep-edit-row select {
      flex: 1; padding: 5px 8px; background: #0f172a; border: 1px solid #334155;
      border-radius: 4px; color: #e2e8f0; font-size: 12px; outline: none;
    }
    .tep-edit-actions { display: flex; gap: 6px; margin-top: 8px; }
    .tep-edit-agents-box {
      max-height: 150px; overflow-y: auto; background: #0f172a;
      border: 1px solid #334155; border-radius: 4px; padding: 4px;
      margin-top: 4px;
    }
    .tep-edit-agents-box label {
      display: flex; align-items: center; gap: 5px; padding: 3px 5px;
      border-radius: 3px; cursor: pointer; font-size: 11px; color: #e2e8f0;
      min-width: auto;
    }
    .tep-edit-agents-box label:hover { background: #334155; }
    .tep-edit-agents-box input { accent-color: #3b82f6; }
    .tep-edit-agent-filter {
      padding: 4px 6px; background: #0f172a; border: 1px solid #334155;
      border-radius: 4px; color: #e2e8f0; font-size: 11px; outline: none;
    }
    .tep-edit-agent-filter:focus { border-color: #3b82f6; }

    /* Bulk actions bar */
    .tep-bulk-bar {
      display: none; background: #1e3a5f; border: 1px solid #3b82f6; border-radius: 8px;
      padding: 10px 12px; margin-bottom: 10px; gap: 8px; align-items: center; flex-wrap: wrap;
    }
    .tep-bulk-bar.active { display: flex; }
    .tep-bulk-bar span { font-size: 12px; font-weight: 600; color: #93c5fd; white-space: nowrap; }
    .tep-bulk-bar select {
      padding: 5px 8px; background: #0f172a; border: 1px solid #334155;
      border-radius: 4px; color: #e2e8f0; font-size: 12px; outline: none;
    }
    .tep-bulk-bar button {
      padding: 5px 12px; border: none; border-radius: 5px; font-size: 12px;
      font-weight: 600; cursor: pointer; transition: background .15s;
    }
    .tep-bulk-apply { background: #3b82f6; color: #fff; }
    .tep-bulk-apply:hover { background: #2563eb; }
    .tep-bulk-delete { background: #7f1d1d; color: #fca5a5; }
    .tep-bulk-delete:hover { background: #991b1b; }
    .tep-test-card-check { accent-color: #3b82f6; margin-right: 4px; cursor: pointer; flex-shrink: 0; }
    .tep-select-bar { display: flex; gap: 8px; margin-bottom: 8px; align-items: center; }
    .tep-select-bar button { background: none; border: none; color: #3b82f6; font-size: 12px; cursor: pointer; padding: 0; }
    .tep-select-bar button:hover { text-decoration: underline; }

    /* Scrollbar */
    #te-panel-root ::-webkit-scrollbar { width: 6px; }
    #te-panel-root ::-webkit-scrollbar-track { background: transparent; }
    #te-panel-root ::-webkit-scrollbar-thumb { background: #334155; border-radius: 3px; }
  `;

  // ---------------------------------------------------------------------------
  // CSP-safe style injection (works on Firefox + Chrome)
  // ---------------------------------------------------------------------------
  function tepInjectCSS(css) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
      return {
        update(newCss) { sheet.replaceSync(newCss); },
        remove() { document.adoptedStyleSheets = document.adoptedStyleSheets.filter(s => s !== sheet); }
      };
    } catch (_) {
      // Fallback for older browsers
      const el = document.createElement('style');
      el.textContent = css;
      (document.head || document.documentElement).appendChild(el);
      return {
        update(newCss) { el.textContent = newCss; },
        remove() { el.remove(); }
      };
    }
  }

  // ---------------------------------------------------------------------------
  // Create DOM
  // ---------------------------------------------------------------------------
  // Create resize gutter
  const resizeHandle = document.createElement('div');
  resizeHandle.id = 'tep-resize-handle';
  document.body.appendChild(resizeHandle);

  const root = document.createElement('div');
  root.id = 'te-panel-root';

  // Floating toggle button — persists even when panel is hidden
  const toggleBtn = document.createElement('div');
  toggleBtn.id = 'tep-toggle-btn';
  toggleBtn.textContent = '\u2716';
  toggleBtn.title = 'Toggle TE Optics panel';
  toggleBtn.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:2147483647;width:44px;height:44px;' +
    'border-radius:50%;background:#3b82f6;color:#fff;font-size:20px;display:flex;align-items:center;' +
    'justify-content:center;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.4);transition:transform .15s,background .15s;' +
    'user-select:none;';
  toggleBtn.addEventListener('mouseenter', () => { toggleBtn.style.transform = 'scale(1.1)'; });
  toggleBtn.addEventListener('mouseleave', () => { toggleBtn.style.transform = ''; });
  toggleBtn.addEventListener('click', () => {
    const isHidden = root.style.display === 'none';
    root.style.display = isHidden ? '' : 'none';
    resizeHandle.style.display = isHidden ? '' : 'none';
    toggleBtn.textContent = isHidden ? '\u2716' : '\u2699\ufe0f';
    if (isHidden) {
      applyWidth(panelWidth);
    } else {
      constrainStyles.update('');
    }
  });
  document.body.appendChild(toggleBtn);

  const mainStyles = tepInjectCSS(STYLES);

  // Push TE page content to the left
  const TEP_WIDTH_KEY = 'tep-panel-width';
  let panelWidth = parseInt(localStorage.getItem(TEP_WIDTH_KEY), 10) || 576;
  const constrainStyles = tepInjectCSS('');
  function applyWidth(w) {
    panelWidth = Math.max(320, Math.min(w, window.innerWidth - 300));
    root.style.setProperty('--tep-width', panelWidth + 'px');
    resizeHandle.style.right = (panelWidth - 3) + 'px';
    localStorage.setItem(TEP_WIDTH_KEY, panelWidth);
    constrainStyles.update(`
      html {
        margin-right: ${panelWidth}px !important;
        overflow-x: hidden !important;
      }
      body {
        overflow-x: hidden !important;
        min-width: 0 !important;
        width: auto !important;
      }
      /* Force all TE content containers to respect available width */
      body > *:not(#te-panel-root):not(#tep-resize-handle):not(script):not(style):not(link) {
        max-width: calc(100vw - ${panelWidth}px) !important;
        overflow-x: auto !important;
      }
    `);
  }
  applyWidth(panelWidth);

  root.insertAdjacentHTML('beforeend', `
    <div class="tep-header" id="tep-drag-handle">
      <h2>TE Optics</h2>
      <button class="tep-dark-toggle" id="tep-dark-toggle" title="Toggle dark mode on TE page">&#9789;</button>
      <button class="tep-close" id="tep-close">&times;</button>
    </div>
    <div class="tep-status" id="tep-status">Detecting session&hellip;</div>

    <!-- Top-level view switcher (filled by renderViewTabsInitial) -->
    <div class="tep-view-tabs" id="tep-view-tabs"></div>

    <div class="tep-body" id="tep-body">
      <!-- ============== CREATE PANEL ============== -->
      <div class="tep-view-panel active" id="tep-panel-create">
        <div class="tep-tabs" id="tep-tabs">
          <div class="tep-tab active" data-type="http-server">HTTP Server</div>
          <div class="tep-tab" data-type="agent-to-server">Agent&rarr;Server</div>
          <div class="tep-tab" data-type="page-load">Page Load</div>
        </div>

        <label class="tep-label">Test Name (use {target} as placeholder for bulk)</label>
        <input class="tep-input" id="tep-testname" value="HTTP Test - {target}" placeholder="My test name">

        <label class="tep-label">Targets (one per line)</label>
        <div class="tep-targets-wrap">
          <textarea class="tep-textarea" id="tep-targets" placeholder="https://example.com&#10;https://another.com"></textarea>
          <div class="tep-targets-gutter" id="tep-targets-gutter" aria-hidden="true"></div>
        </div>

        <div id="tep-a2s-fields" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;margin:8px 0;">
          <div>
            <label class="tep-label">Protocol</label>
            <select class="tep-select" id="tep-a2s-protocol" style="width:auto;">
              <option value="TCP-SACK" selected>TCP / SACK</option>
              <option value="TCP-SYN">TCP / SYN</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>
          <div id="tep-a2s-tcp-opts" style="display:contents;">
            <div>
              <label class="tep-label">Port</label>
              <input class="tep-input" id="tep-a2s-port" type="number" value="443" min="1" max="65535" style="width:80px;">
            </div>
            <label style="display:flex;align-items:center;gap:4px;font-size:12px;color:#94a3b8;cursor:pointer;padding-bottom:2px;">
              <input type="checkbox" id="tep-a2s-insession" checked> In-Session
            </label>
          </div>
        </div>

        <label class="tep-label">Test Interval</label>
        <select class="tep-select" id="tep-interval">
          <option value="60">1 minute</option>
          <option value="120" selected>2 minutes</option>
          <option value="300">5 minutes</option>
          <option value="600">10 minutes</option>
          <option value="900">15 minutes</option>
          <option value="1800">30 minutes</option>
          <option value="3600">60 minutes</option>
        </select>


        <div class="tep-section-title">
          Agents
          <button class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-load-agents" style="float:right;">Reload Agents</button>
        </div>
        <div class="tep-agent-filter-wrap">
          <input class="tep-agent-filter" id="tep-agent-filter" placeholder="Filter agents&hellip;">
          <button type="button" class="tep-agent-filter-clear" id="tep-agent-filter-clear" title="Clear filter" aria-label="Clear filter">&times;</button>
        </div>
        <div class="tep-agents-box" id="tep-agents-box">
          <span class="tep-log-info">Agents will load after auth&hellip;</span>
        </div>

        <div class="tep-actions">
          <button class="tep-btn tep-btn-primary" id="tep-create">Create Tests</button>
          <button class="tep-btn tep-btn-secondary" id="tep-retry-auth">Retry Auth</button>
          <button class="tep-btn tep-btn-secondary" id="tep-clear-log">Clear Log</button>
        </div>
      </div>

      <!-- ============== MANAGE PANEL ============== -->
      <div class="tep-view-panel" id="tep-panel-manage">
        <div class="tep-manage-toolbar">
          <select id="tep-manage-type-filter">
            <option value="">All Types</option>
            <option value="Http">HTTP Server</option>
            <option value="A2s">Agent→Server</option>
            <option value="Page">Page Load</option>
          </select>
          <input id="tep-manage-search" placeholder="Search tests&hellip;">
          <select id="tep-manage-sort" style="width:auto;">
            <option value="default">Sort: Default</option>
            <option value="name">Sort: Name</option>
            <option value="modified">Sort: Date Modified</option>
            <option value="created">Sort: Date Created</option>
          </select>
          <button class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-manage-load">Load Tests</button>
        </div>
        <div class="tep-bulk-bar" id="tep-bulk-bar">
          <span id="tep-bulk-count">0 selected</span>
          <select id="tep-bulk-action">
            <option value="">— Bulk Action —</option>
            <option value="enable">Enable All</option>
            <option value="disable">Disable All</option>
            <option value="interval">Change Interval</option>
            <option value="protocol">Change Protocol</option>
            <option value="delete">Delete All</option>
          </select>
          <select id="tep-bulk-protocol" style="display:none;">
            <option value="TCP-SACK">TCP / SACK</option>
            <option value="TCP-SYN">TCP / SYN</option>
            <option value="ICMP">ICMP</option>
          </select>
          <label id="tep-bulk-insession" style="display:none;font-size:11px;color:#94a3b8;cursor:pointer;align-items:center;gap:4px;">
            <input type="checkbox" id="tep-bulk-insession-cb" checked> In-Session
          </label>
          <select id="tep-bulk-interval" style="display:none;">
            <option value="60">1 min</option>
            <option value="120">2 min</option>
            <option value="300">5 min</option>
            <option value="600">10 min</option>
            <option value="900">15 min</option>
            <option value="1800">30 min</option>
            <option value="3600">60 min</option>
          </select>
          <button class="tep-bulk-apply" id="tep-bulk-apply">Apply</button>
        </div>
        <div class="tep-select-bar" id="tep-select-bar" style="display:none;">
          <button id="tep-select-all">Select All</button>
          <button id="tep-select-none">Deselect All</button>
          <button id="tep-select-filtered">Select Filtered</button>
        </div>
        <div class="tep-test-count" id="tep-test-count"></div>
        <div class="tep-test-list" id="tep-test-list">
          <span class="tep-log-info">Click "Load Tests" or switch to this tab after auth.</span>
        </div>
      </div>

      <!-- ============== DASHBOARD TOOLS (/dashboard only) ============== -->
      <div class="tep-view-panel" id="tep-panel-dashboard">
        <div id="tep-dash-panel-backup" class="tep-dash-tab-panel active">
          <div class="tep-dash-card">
            <div class="tep-dash-meta" id="tep-dash-meta">Nothing loaded yet — use Refresh import.</div>
            <label class="tep-label">Dashboard JSON (backup)</label>
            <details class="tep-dash-json-details" id="tep-dash-json-details">
              <summary>
                <span class="tep-dash-json-sum tep-dash-json-sum-empty" id="tep-dash-json-summary">No JSON yet — expand to edit</span>
                <span class="tep-dash-json-chev" aria-hidden="true">&#9654;</span>
              </summary>
              <div class="tep-dash-json-details-body">
                <textarea class="tep-textarea tep-dash-json" id="tep-dash-json" spellcheck="false" placeholder="{ }"></textarea>
              </div>
            </details>
            <div class="tep-dash-row">
              <button type="button" class="tep-btn tep-btn-primary tep-btn-sm" id="tep-dash-refresh">Refresh import</button>
            </div>
            <div class="tep-dash-actions">
              <button type="button" class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-dash-download">Save as file…</button>
            </div>

            <div class="tep-dash-cleanup" id="tep-dash-cleanup">
              <div class="tep-dash-section-title">Dashboard cleanup</div>
              <p class="tep-dash-cleanup-meta" id="tep-dash-cleanup-meta">Not loaded yet.</p>
              <div class="tep-dash-cleanup-toolbar">
                <button type="button" class="tep-btn tep-btn-primary tep-btn-sm" id="tep-dash-cleanup-refresh">Load dashboards in account group</button>
                <button type="button" class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-dash-cleanup-sort" title="Toggle list order">Sort: newest first</button>
                <button type="button" class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-dash-cleanup-select-none">Select none</button>
                <button type="button" class="tep-btn tep-btn-danger tep-btn-sm" id="tep-dash-cleanup-delete">Delete selected…</button>
              </div>
              <div class="tep-dash-cleanup-list" id="tep-dash-cleanup-list"></div>
            </div>
          </div>
        </div>

        <div id="tep-dash-panel-restore" class="tep-dash-tab-panel">
          <div class="tep-dash-card tep-dash-restore-card">
            <div class="tep-dash-meta" id="tep-dash-restore-meta">No restore payload yet — use Open import file…</div>

            <label class="tep-label">Dashboard JSON to restore</label>
            <details class="tep-dash-json-details" id="tep-dash-restore-json-details">
              <summary>
                <span class="tep-dash-json-sum tep-dash-json-sum-empty" id="tep-dash-restore-json-summary">No JSON yet — expand to paste or use Open import file…</span>
                <span class="tep-dash-json-chev" aria-hidden="true">&#9654;</span>
              </summary>
              <div class="tep-dash-json-details-body">
                <textarea class="tep-textarea tep-dash-json" id="tep-dash-restore-json" spellcheck="false" placeholder="{ }"></textarea>
              </div>
            </details>

            <div class="tep-dash-actions" style="margin-top:10px;">
              <button type="button" class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-dash-restore-import-file-btn">Open import file…</button>
              <input type="file" id="tep-dash-restore-import-file" accept="application/json,.json" style="display:none;">
            </div>

            <label class="tep-label" for="tep-dash-restore-title">New dashboard title (optional)</label>
            <input type="text" class="tep-input" id="tep-dash-restore-title" placeholder="Leave blank to keep the title from the imported JSON" autocomplete="off">

            <label class="tep-label" for="tep-dash-restore-agent-mode">Agents &amp; widget filters on restore</label>
            <select class="tep-select" id="tep-dash-restore-agent-mode" style="width:100%;">
              <option value="keep" selected>Keep original (from backup)</option>
              <option value="strip">Remove all widget filters (and clear virtual-agent fields)</option>
            </select>

            <div id="tep-dash-restore-agents-wrap" class="tep-dash-restore-agents-wrap" style="display:none;">
              <p class="tep-dash-hint" id="tep-dash-restore-agent-note" style="margin:0 0 6px;">Every <code>filters</code> object in the dashboard JSON is deleted, and virtual-agent id fields (vAgentIds, agentSet, etc.) are cleared.</p>
            </div>

            <div class="tep-dash-row" style="margin-top:14px;">
              <button type="button" class="tep-btn tep-btn-danger tep-btn-sm" id="tep-dash-restore" style="flex:1;">Restore to ThousandEyes…</button>
            </div>
          </div>
        </div>

        <details class="tep-dash-details">
          <summary>Advanced — diagnostics <span class="tep-dash-chevron" aria-hidden="true">&#9654;</span></summary>
          <div class="tep-dash-details-inner tep-dash-advanced-inner">
            <label style="display:flex;align-items:flex-start;gap:8px;font-size:12px;color:#94a3b8;cursor:pointer;line-height:1.45;margin-bottom:10px;">
              <input type="checkbox" id="tep-dash-sniff-ajax" checked style="margin-top:3px;flex-shrink:0;">
              <span>Log dashboard-related <code>/ajax/</code> and <code>/namespace/dash-api</code> JSON to the browser console (filter <code>[TE Optics]</code>).</span>
            </label>
            <div class="tep-dash-actions" style="margin-top:0;">
              <button type="button" class="tep-btn tep-btn-secondary tep-btn-sm" id="tep-dash-copy-debug">Copy diagnostics report</button>
            </div>
            <p style="margin:10px 0 0;font-size:11px;color:#64748b;line-height:1.45;">
              Console flags: <code>window.__TEP_OPTICS_PROBE_SPECULATIVE__ = true</code> then Retry Auth;
              <code>window.__TEP_OPTICS_FORCE_DASH_PROBE__ = true</code> then reload backup;
              <code>window.__TEP_OPTICS_VERBOSE_DASH_PROBES__ = true</code> for probe lines in the log.
            </p>
          </div>
        </details>
      </div>

      <!-- Author: Christopher Hunt -->
      <div class="tep-attribution" id="tep-attribution" aria-label="Legal and attribution">
        <strong style="color:#cbd5e1;">TE Optics</strong>
        — <a href="https://github.com/lucidium2000/TE-Optics" target="_blank" rel="noopener noreferrer">GitHub</a>
        · not affiliated with Cisco or ThousandEyes · provided as-is; no warranty or support.
      </div>

      <!-- Log (shared) -->
      <div class="tep-log-wrap">
        <div class="tep-log-toolbar">
          <button type="button" class="tep-log-toggle" id="tep-log-toggle"><span class="tep-log-arrow">&#9654;</span> Log</button>
          <button type="button" class="tep-log-copy" id="tep-log-copy" title="Copy entire log to clipboard">Copy log</button>
        </div>
        <div class="tep-log" id="tep-log"></div>
      </div>
    </div>
  `);

  document.body.appendChild(root);

  // ---------------------------------------------------------------------------
  // View tabs + panels (tests vs /dashboard)
  // ---------------------------------------------------------------------------
  function renderViewTabsInitial() {
    const tabs = root.querySelector('#tep-view-tabs');
    const h2 = root.querySelector('.tep-header h2');
    const pDash = root.querySelector('#tep-panel-dashboard');
    const pCreate = root.querySelector('#tep-panel-create');
    const pManage = root.querySelector('#tep-panel-manage');
    if (!tabs || !pDash || !pCreate || !pManage) return;

    if (isDashboardToolsPage()) {
      if (h2) h2.textContent = 'TE Optics';
      tabs.innerHTML =
        '<div class="tep-view-tab active" data-view="dashboard" data-dash-tab="backup">Backup</div>' +
        '<div class="tep-view-tab" data-view="dashboard" data-dash-tab="restore">Restore</div>';
      pCreate.classList.remove('active');
      pManage.classList.remove('active');
      pDash.classList.add('active');
    } else {
      tabs.innerHTML = '<div class="tep-view-tab active" data-view="create">Create Tests</div>' +
        '<div class="tep-view-tab" data-view="manage">Manage Tests</div>';
      pDash.classList.remove('active');
      pCreate.classList.add('active');
    }
  }

  renderViewTabsInitial();

  // ---------------------------------------------------------------------------
  // Refs
  // ---------------------------------------------------------------------------
  const $ = (sel) => root.querySelector(sel);
  const statusEl = $('#tep-status');
  const logEl = $('#tep-log');
  const agentsBox = $('#tep-agents-box');
  const filterInput = $('#tep-agent-filter');
  const tabsContainer = $('#tep-tabs');
  let currentType = 'http-server';

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------
  function setStatus(text, cls) {
    statusEl.textContent = text;
    statusEl.className = 'tep-status' + (cls ? ' ' + cls : '');
  }

  function log(msg, cls) {
    const span = document.createElement('span');
    span.className = cls || 'tep-log-info';
    span.textContent = msg + '\n';
    logEl.appendChild(span);
    logEl.scrollTop = logEl.scrollHeight;
  }

  function toast(msg, type) {
    const el = document.createElement('div');
    el.className = 'tep-toast ' + (type === 'ok' ? 'tep-toast-ok' : 'tep-toast-err');
    el.textContent = msg;
    const body = root.querySelector('.tep-body');
    body.insertBefore(el, body.firstChild);
    setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 3500);
    setTimeout(() => el.remove(), 4000);
  }

  function toastProcessing(msg) {
    const el = document.createElement('div');
    el.className = 'tep-toast tep-toast-processing';
    el.textContent = msg || 'Processing…';
    const body = root.querySelector('.tep-body');
    body.insertBefore(el, body.firstChild);
    return () => el.remove();
  }

  /** Show × in filter wrap when text present; clear runs onClear (e.g. re-render agent list). */
  function wireAgentFilterClear(wrap, input, onClear) {
    if (!wrap || !input) return;
    const btn = wrap.querySelector('.tep-agent-filter-clear');
    if (!btn) return;
    function sync() {
      btn.style.display = input.value.trim() ? 'flex' : 'none';
    }
    input.addEventListener('input', sync);
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      input.value = '';
      sync();
      input.focus();
      if (typeof onClear === 'function') onClear();
    });
    sync();
  }

  // ---------------------------------------------------------------------------
  // CSRF detection (Angular apps often use XSRF-TOKEN cookie)
  // ---------------------------------------------------------------------------
  function detectCsrfToken() {
    try {
      const patterns = ['XSRF-TOKEN', 'csrf_token', 'csrftoken', '_csrf'];
      for (const c of document.cookie.split(';')) {
        const eq = c.indexOf('=');
        if (eq < 0) continue;
        const name = c.substring(0, eq).trim();
        if (patterns.some(p => name.toUpperCase() === p.toUpperCase())) {
          const val = decodeURIComponent(c.substring(eq + 1).trim());
          if (val) {
            log(`Found CSRF cookie "${name}"`, 'tep-log-info');
            return { headerName: 'X-' + name, value: val };
          }
        }
      }
    } catch { /* no access */ }
    return null;
  }

  // Check if running on a ThousandEyes page
  function isOnTEPage() {
    return /thousandeyes\.com$/i.test(window.location.hostname);
  }

  function readBrowserCookie(name) {
    try {
      const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const m = document.cookie.match(new RegExp('(?:^|;\\s*)' + esc + '=([^;]*)'));
      return m ? decodeURIComponent(m[1].trim()) : '';
    } catch (_) {
      return '';
    }
  }

  /** Headers the SPA sends for /namespace/dash-api/* (dashboard GET, poll POST, …); cookies alone are often not enough. */
  function buildDashNamespaceHeaders() {
    const h = {
      'Accept': 'application/json, text/plain, */*',
      'x-dash-client-id': 'app'
    };
    if (teInitData && teInitData._currentAid != null && teInitData._currentAid !== '') {
      h['x-thousandeyes-aid'] = String(teInitData._currentAid);
    }
    const uid = readBrowserCookie('teUid');
    if (uid) h['x-thousandeyes-uid'] = uid;
    const hero = readBrowserCookie('teHeroUserId');
    if (hero) h['x-thousandeyes-heroid'] = hero;
    if (teInitData && typeof teInitData === 'object') {
      const pick = (a, b, c) => teInitData[a] ?? teInitData[b] ?? teInitData[c];
      const orgId = pick('orgId', '_orgId', 'organizationId');
      if (orgId != null && String(orgId) !== '') h['x-thousandeyes-orgid'] = String(orgId);
      const orgName = pick('orgName', '_orgName', 'organizationName');
      if (typeof orgName === 'string' && orgName) h['x-thousandeyes-orgname'] = orgName;
      const acctName = pick('accountName', 'accountGroupName', 'currentAccountName');
      if (typeof acctName === 'string' && acctName) h['x-thousandeyes-accountname'] = acctName;
      const acctType = teInitData.accountType;
      if (typeof acctType === 'string' && acctType) h['x-thousandeyes-accounttype'] = acctType;
      const ver = pick('version', 'appVersion', 'teVersion');
      if (typeof ver === 'string' && ver) h['x-thousandeyes-version'] = ver;
    }
    return h;
  }

  function dashPollJsonBody(dashboardId) {
    return JSON.stringify({
      dashboardId,
      dashboardModifiedDate: new Date().toISOString().replace('Z', '+00:00'),
      statuses: []
    });
  }

  // Internal AJAX caller — same-origin, cookies sent automatically
  function ajax(path, options = {}) {
    const pathStr = path == null ? '' : String(path);
    const isDashNs = pathStr.includes('/namespace/dash-api');
    const headers = {
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      ...(isDashNs ? buildDashNamespaceHeaders() : {}),
      ...(options.headers || {})
    };
    if (options.body) headers['Content-Type'] = 'application/json';
    if (csrfToken) headers[csrfToken.headerName] = csrfToken.value;
    return fetch(path, { ...options, headers, credentials: 'include' });
  }

  function withAidQuery(path, aid) {
    if (aid == null || aid === '') return path;
    return path.includes('?') ? `${path}&aid=${encodeURIComponent(aid)}` : `${path}?aid=${encodeURIComponent(aid)}`;
  }

  function buildDashboardProbeUrls(aid) {
    const id = extractDashboardIdFromLocation();
    const paths = [];
    const q = (p) => withAidQuery(p, aid);
    if (id) {
      paths.push(q(`/ajax/dashboards/${id}`));
      paths.push(q(`/ajax/dashboard/${id}`));
      paths.push(q(`/ajax/user/dashboards/${id}`));
      paths.push(q(`/ajax/settings/dashboards/${id}`));
      paths.push(q(`/ajax/settings/user/dashboards/${id}`));
      paths.push(q(`/ajax/dashboards/info/${id}`));
      paths.push(q(`/ajax/dashboards/edit/${id}`));
    }
    if (!id) {
      paths.push(q('/ajax/dashboards'));
      paths.push(q('/ajax/user/dashboards'));
      paths.push(q('/ajax/settings/dashboards'));
      paths.push(q('/ajax/dashboard/current'));
      paths.push(q('/ajax/dashboards/current'));
      paths.push(q('/ajax/user/dashboard/current'));
    }
    if (window.__TEP_OPTICS_PROBE_SPECULATIVE__ === true && !id) {
      paths.push(q('/ajax/visualization/dashboards'));
      paths.push(q('/ajax/reporting/dashboards'));
      paths.push(q('/ajax/home/dashboard'));
      paths.push(q('/ajax/ui/dashboard'));
    }
    return paths;
  }

  /** GET /namespace/dash-api/dashboard — TE returns the full dashboard JSON (same headers as poll). */
  async function probeNamespaceDashDashboardGet(aid, dashboardId, verbose) {
    const q = (p) => withAidQuery(p, aid);
    const candidates = [];
    if (dashboardId) {
      candidates.push(q(`/namespace/dash-api/dashboard/${encodeURIComponent(dashboardId)}`));
      candidates.push(q(`/namespace/dash-api/dashboard?dashboardId=${encodeURIComponent(dashboardId)}`));
    } else {
      candidates.push(q('/namespace/dash-api/dashboard'));
    }
    for (const path of candidates) {
      try {
        const resp = await ajax(path, { method: 'GET' });
        const ct = (resp.headers && resp.headers.get && resp.headers.get('content-type')) || '';
        const raw = await resp.text();
        const data = tryParseJsonText(raw);
        if (resp.ok && data != null) {
          let useData = unwrapIfSingleElementArray(data);
          if (dashboardId) {
            const narrowed = selectDashboardForFocusFromAggregate(useData, dashboardId);
            if (narrowed != null) {
              useData = narrowed;
            } else if (Array.isArray(useData)) {
              pushProbeHistory(path + ' [GET dash-api/dashboard]', resp.status, ct, 'JSON array/list — no row matching URL dashboard id');
              if (verbose) log(`GET ${path} → aggregate array, no matching id ${dashboardId}`, 'tep-log-info');
              dashConsole('info', 'dash-api/dashboard GET skipped — list with no id match', { path, dashboardId });
              continue;
            }
          }
          if (Array.isArray(useData)) {
            pushProbeHistory(path + ' [GET dash-api/dashboard]', resp.status, ct, 'JSON array (need one object) — try next URL');
            if (verbose) log(`GET ${path} → root is multi-element array, skipping`, 'tep-log-info');
            continue;
          }
          if (dashboardId) {
            const pid = getPayloadDashboardId(useData);
            if (pid != null && String(pid) !== String(dashboardId)) {
              pushProbeHistory(path + ' [GET dash-api/dashboard]', resp.status, ct, 'OK JSON but id mismatch vs URL dashboardId — skipped');
              if (verbose) log(`GET ${path} → body id ${pid} !== URL ${dashboardId}`, 'tep-log-info');
              dashConsole('warn', 'dash-api/dashboard GET skipped — id mismatch', { path, pid, dashboardId });
              continue;
            }
          }
          const sc = scoreDashboardPayload(useData);
          dashProbeCacheFailAid = null;
          pushProbeHistory(path + ' [GET dash-api/dashboard]', resp.status, ct, '(OK JSON)');
          log(`Dashboard definition GET OK: ${path} (heuristic score ${sc})`, 'tep-log-ok');
          dashConsole('info', 'dash-api/dashboard GET OK', { path, score: sc, keys: topLevelKeysLabel(useData) });
          return { url: path, data: useData, method: 'GET' };
        }
        if (resp.ok) {
          pushProbeHistory(path + ' [GET dash-api/dashboard]', resp.status, ct, '200 non-JSON: ' + raw.slice(0, 220));
        } else {
          let snippet = '';
          try {
            snippet = (await resp.clone().text()).slice(0, 500);
          } catch (_) {
            snippet = '(unreadable body)';
          }
          pushProbeHistory(path + ' [GET dash-api/dashboard]', resp.status, ct, snippet.slice(0, 500));
          if (verbose) log(`GET ${path} → HTTP ${resp.status}`, 'tep-log-info');
        }
      } catch (e) {
        pushProbeHistory(path + ' [GET dash-api/dashboard]', -1, '', e.message || String(e));
        if (verbose) log(`GET ${path} → ${e.message}`, 'tep-log-info');
        dashConsole('error', 'dash-api/dashboard GET exception', { path, error: e.message });
      }
    }
    return null;
  }

  async function probeNamespaceDashPoll(dashboardId, verbose) {
    const path = '/namespace/dash-api/poll';
    const body = dashPollJsonBody(dashboardId);
    try {
      const resp = await ajax(path, { method: 'POST', body });
      const ct = (resp.headers && resp.headers.get && resp.headers.get('content-type')) || '';
      const raw = await resp.text();
      const data = tryParseJsonText(raw);
      if (resp.ok && data != null) {
        if (isNamespacePollMissingDashboardDoc(data)) {
          pushProbeHistory(path + ' [POST poll]', resp.status, ct, 'JSON but no backup payload (e.g. NOCHANGE / dashboard null)');
          log('Dashboard poll: OK JSON but no full dashboard document (typical NOCHANGE). Poll is for deltas — for backup, copy the Network request whose JSON contains widgets/layout.', 'tep-log-info');
          dashConsole('info', 'poll JSON has no dashboard backup payload', { status: data.status, keys: topLevelKeysLabel(data) });
          return null;
        }
        if (dashboardId) {
          const pid = getPayloadDashboardId(data);
          if (pid != null && String(pid) !== String(dashboardId)) {
            pushProbeHistory(path + ' [POST poll]', resp.status, ct, 'OK JSON but id mismatch vs URL dashboardId — skipped');
            dashConsole('warn', 'dashboard poll POST skipped — id mismatch', { pid, dashboardId });
            return null;
          }
        }
        dashProbeCacheFailAid = null;
        pushProbeHistory(path + ' [POST poll]', resp.status, ct, '(OK JSON with dashboard-ish body)');
        log(`Dashboard poll POST OK: ${path} (dashboard payload)`, 'tep-log-ok');
        dashConsole('info', 'dashboard poll POST OK', { path, status: resp.status, keys: topLevelKeysLabel(data) });
        return { url: path, data, method: 'POST' };
      }
      if (resp.ok) {
        pushProbeHistory(path + ' [POST poll]', resp.status, ct, '200 non-JSON: ' + raw.slice(0, 220));
        if (verbose) log(`Dashboard poll POST → 200 not JSON (${ct}) ${raw.slice(0, 100)}`, 'tep-log-info');
        dashConsole('info', 'dashboard poll POST 200 non-JSON', { path, ct, preview: raw.slice(0, 120) });
      } else {
        let snippet = '';
        try {
          snippet = (await resp.clone().text()).slice(0, 500);
        } catch (_) {
          snippet = '(unreadable body)';
        }
        pushProbeHistory(path + ' [POST poll]', resp.status, ct, snippet.slice(0, 500));
        const oneLine = summarizeProbeFailureSnippet(snippet, resp.status);
        if (verbose) log(`Dashboard poll POST → ${oneLine}`, 'tep-log-info');
        dashConsole('warn', 'dashboard poll POST non-OK', { path, status: resp.status, summary: oneLine });
      }
    } catch (e) {
      pushProbeHistory(path + ' [POST poll]', -1, '', e.message || String(e));
      if (verbose) log(`Dashboard poll POST → error: ${e.message}`, 'tep-log-info');
      dashConsole('error', 'dashboard poll POST exception', { path, error: e.message });
    }
    return null;
  }

  async function fetchDashboardFromProbes() {
    const aid = teInitData && teInitData._currentAid != null ? String(teInitData._currentAid) : '';
    const key = aid || '_noaid';
    const verbose = window.__TEP_OPTICS_VERBOSE_DASH_PROBES__ === true;

    if (window.__TEP_OPTICS_FORCE_DASH_PROBE__ === true) {
      window.__TEP_OPTICS_FORCE_DASH_PROBE__ = false;
      dashProbeCacheFailAid = null;
    }
    if (dashProbeCacheFailAid != null && dashProbeCacheFailAid !== key) {
      dashProbeCacheFailAid = null;
    }

    const dashId = extractDashboardIdFromLocation();
    const docHit = await probeNamespaceDashDashboardGet(aid, dashId, verbose);
    if (docHit) return docHit;
    if (dashId) {
      const pollHit = await probeNamespaceDashPoll(dashId, verbose);
      if (pollHit) return pollHit;
    }

    if (dashProbeCacheFailAid === key) {
      dashConsole('info', 'dashboard probes skipped (cached — all built-in GET URLs already failed for this aid)', { aid: key });
      return null;
    }

    const urls = buildDashboardProbeUrls(aid);
    dashConsole('info', 'dashboard probes starting', {
      aid: aid || '(none)',
      paths: urls.length,
      parsedId: dashId
    });
    for (const path of urls) {
      try {
        const resp = await ajax(path, { method: 'GET' });
        const ct = (resp.headers && resp.headers.get && resp.headers.get('content-type')) || '';
        if (resp.ok) {
          const raw = await resp.text();
          const data = tryParseJsonText(raw);
          if (data != null) {
            if (dashId) {
              const pid = getPayloadDashboardId(data);
              if (pid != null && String(pid) !== String(dashId)) {
                pushProbeHistory(path, resp.status, ct, '(JSON id mismatch vs URL dashboardId — skipped)');
                if (verbose) log(`Dashboard probe skip (wrong id): ${path} body id ${pid} vs URL ${dashId}`, 'tep-log-info');
                dashConsole('info', 'dashboard probe skipped — JSON id does not match URL', { path, pid, dashId });
                continue;
              }
            }
            dashProbeCacheFailAid = null;
            pushProbeHistory(path, resp.status, ct, '(OK JSON)');
            log(`Dashboard probe OK: ${path} → ${topLevelKeysLabel(data)}`, 'tep-log-ok');
            dashConsole('info', 'dashboard probe OK', { path, status: resp.status, keys: topLevelKeysLabel(data) });
            return { url: path, data, method: 'GET' };
          }
          pushProbeHistory(path, resp.status, ct, '200 non-JSON: ' + raw.slice(0, 220));
          if (verbose) {
            log(`Dashboard probe ${path} → 200 but body not JSON (${ct || 'no CT'}) ${raw.slice(0, 100)}`, 'tep-log-info');
          }
          dashConsole('info', 'dashboard probe 200 non-JSON body', { path, ct, preview: raw.slice(0, 120) });
          continue;
        }
        let snippet = '';
        try {
          snippet = (await resp.clone().text()).slice(0, 500);
        } catch (_) {
          snippet = '(unreadable body)';
        }
        const historySnippet = isHtmlLikeResponse(snippet)
          ? snippet.slice(0, 100).replace(/\s+/g, ' ') + '…'
          : snippet.slice(0, 500);
        pushProbeHistory(path, resp.status, ct, historySnippet);
        const oneLine = summarizeProbeFailureSnippet(snippet, resp.status);
        if (verbose) {
          log(`Dashboard probe ${path} → ${oneLine}`, 'tep-log-info');
        }
        dashConsole('warn', 'dashboard probe non-OK', { path, status: resp.status, ct, summary: oneLine });
      } catch (e) {
        pushProbeHistory(path, -1, '', e.message || String(e));
        if (verbose) {
          log(`Dashboard probe ${path} → error: ${e.message}`, 'tep-log-info');
        }
        dashConsole('error', 'dashboard probe exception', { path, error: e.message });
      }
    }
    dashProbeCacheFailAid = key;
    dashConsole('warn', 'dashboard probes exhausted — no 200 JSON', { tried: urls.length });
    log(`Built-in dashboard probes (${urls.length} GET URLs, aid=${key}${dashId ? '; dash GET + poll tried before list' : ''}): no JSON snapshot. Prefer URL with ?dashboardId= on /dashboard. Copy troubleshooting report or paste a Network URL under “Load from a copied request URL”. (Repeats skip HTTP — set window.__TEP_OPTICS_FORCE_DASH_PROBE__=true to probe again.)`, 'tep-log-info');
    return null;
  }

  async function mergeBestDashboardJson() {
    const focusId = extractDashboardIdFromLocation();
    const captured = pickBestDashboardLikePayload(focusId);
    const probed = await fetchDashboardFromProbes();
    let best = null;
    let bestScore = -1;
    let source = '';
    if (captured && captured.score > bestScore) {
      best = captured.data;
      bestScore = captured.score;
      source = captured.source + ' @ ' + captured.path;
    }
    if (probed) {
      let ps = scoreDashboardPayload(probed.data);
      if ((probed.url || '').includes('dash-api/poll') && isNamespacePollMissingDashboardDoc(probed.data)) ps = -1;
      if (ps > bestScore) {
        best = probed.data;
        bestScore = ps;
        source = (probed.method || 'GET') + ' ' + probed.url;
      }
    }
    if (focusId && best != null) {
      const sliced = selectDashboardForFocusFromAggregate(best, focusId);
      if (sliced != null) {
        best = sliced;
        bestScore = scoreDashboardPayload(sliced);
        source = (source || 'merged') + ' · row for URL dashboard id';
      }
    }
    dashConsole('info', 'mergeBestDashboardJson', {
      focusDashboardId: focusId || '(none)',
      bestScore,
      source: source || '(none)',
      hadCapture: !!captured,
      hadProbe: !!probed,
      captureScore: captured ? captured.score : null,
      sniffBodies: TEP_DASH_SNIFF_BODIES.length,
      nonJson200Ajax: TEP_DASH_NONJSON_200.length,
      probeScore: probed ? scoreDashboardPayload(probed.data) : null
    });
    return { json: best, source, score: bestScore };
  }

  function buildDashboardDebugReport() {
    const lines = [];
    lines.push('=== TE Optics dashboard troubleshooting report ===');
    lines.push('Note: Dashboard data may arrive as non-JSON /ajax/ or /namespace/dash-api (HTML fragment, script, empty), or outside fetch/XHR (WebSocket, shared worker, iframe). This report lists what the page hook saw.');
    lines.push('generatedAt: ' + new Date().toISOString());
    lines.push('href: ' + (typeof location !== 'undefined' ? location.href : ''));
    lines.push('pathname: ' + (typeof location !== 'undefined' ? location.pathname : ''));
    lines.push('search: ' + (typeof location !== 'undefined' ? location.search : ''));
    lines.push('hash: ' + (typeof location !== 'undefined' ? location.hash : ''));
    lines.push('extractedDashboardId: ' + String(extractDashboardIdFromLocation()));
    try {
      const m = typeof document !== 'undefined' && document.cookie && document.cookie.match(/(?:^|;\s*)teAccount=([^;]*)/);
      lines.push('teAccountCookie: ' + (m ? decodeURIComponent(m[1]) : '(none)'));
    } catch (_) {
      lines.push('teAccountCookie: (error reading cookie)');
    }
    lines.push('teInitData._currentAid: ' + (teInitData && teInitData._currentAid != null ? String(teInitData._currentAid) : '(unset)'));
    if (teInitData && typeof teInitData === 'object') {
      lines.push('teInitData keys (excl. _currentAid): ' + Object.keys(teInitData).filter(k => k !== '_currentAid').slice(0, 60).join(', '));
    }
    lines.push('csrfHeader: ' + (csrfToken ? csrfToken.headerName + ' set' : '(none)'));
    lines.push('sniffAllAjaxJson: ' + String(window.__TEP_OPTICS_SNIFF_AJAX__ !== false));
    lines.push('probeSpeculativeUrls: ' + String(window.__TEP_OPTICS_PROBE_SPECULATIVE__ === true));
    lines.push('dashProbeCacheFailAid: ' + (dashProbeCacheFailAid != null ? String(dashProbeCacheFailAid) : '(none — probes not cached or success cleared cache)'));
    lines.push('');
    lines.push('--- Built-in probes: GET /namespace/dash-api/dashboard/{id} + ?dashboardId= + GET /ajax guesses + POST poll (most recent first) ---');
    for (const row of TEP_DASH_PROBE_HISTORY) {
      lines.push(JSON.stringify(row));
    }
    lines.push('');
    lines.push('--- Captures (dashboard under /ajax/, or any /namespace/dash-api) ---');
    for (const e of TEP_DASH_CAPTURE.entries) {
      lines.push(JSON.stringify({
        url: e.url,
        score: e.score,
        t: e.t,
        keys: topLevelKeysLabel(e.data)
      }));
    }
    lines.push('');
    lines.push('--- Sniffed successful JSON: /ajax/ or /namespace/dash-api (fetch + XHR) ---');
    for (const s of TEP_DASH_AJAX_SNIFF) {
      lines.push(JSON.stringify(s));
    }
    lines.push('');
    lines.push('--- HTTP 200 responses (same sniff paths) that were NOT JSON (Content-Type + body hint) ---');
    if (!TEP_DASH_NONJSON_200.length) {
      lines.push('(none recorded — enable console JSON sniff in Troubleshooting, use the dashboard, then Refresh import again)');
    } else {
      for (const n of TEP_DASH_NONJSON_200) {
        lines.push(JSON.stringify(n));
      }
    }
    lines.push('');
    lines.push('--- Sniffed bodies scored as dashboard-like (score>=' + TEP_DASH_SNIFF_MIN_SCORE + ', JSON not included) ---');
    for (const b of TEP_DASH_SNIFF_BODIES) {
      lines.push(JSON.stringify({
        path: b.path,
        score: b.score,
        via: b.via,
        keys: topLevelKeysLabel(b.data),
        t: b.t
      }));
    }
    lines.push('');
    lines.push('--- Resource timing: recent same-origin /ajax/ or /namespace/dash-api URLs (path only) ---');
    try {
      const entries = performance.getEntriesByType('resource');
      const ajaxish = [];
      for (const e of entries) {
        if (!e.name || typeof e.name !== 'string') continue;
        if (!e.name.includes('/ajax/') && !e.name.toLowerCase().includes('/namespace/dash-api')) continue;
        try {
          const u = new URL(e.name, window.location.origin);
          if (u.hostname.replace(/^www\./, '') !== window.location.hostname.replace(/^www\./, '')) continue;
          ajaxish.push(u.pathname);
        } catch (_) {
          ajaxish.push(e.name.split('?')[0].slice(0, 120));
        }
      }
      const uniq = [...new Set(ajaxish)];
      uniq.slice(-50).forEach(p => lines.push(p));
    } catch (e) {
      lines.push('(unavailable: ' + (e.message || e) + ')');
    }
    lines.push('');
    lines.push('--- What to send back ---');
    lines.push('1) This full report text, OR');
    lines.push('2) DevTools Console: all lines containing [TE Optics] after Refresh import, OR');
    lines.push('3) Network tab: one successful JSON request that loads your dashboard widgets — copy Request URL (path + query).');
    return lines.join('\n');
  }

  async function refreshDashboardEditor() {
    const meta = root.querySelector('#tep-dash-meta');
    const ta = root.querySelector('#tep-dash-json');
    if (!meta || !ta) return;
    meta.textContent = 'Refreshing import…';
    dashConsole('info', 'Refresh import clicked');
    const { json, source, score } = await mergeBestDashboardJson();
    if (json != null) {
      ta.value = JSON.stringify(json, null, 2);
      meta.textContent = `Backup loaded · source ${source} (score ${score}) · ${new Date().toISOString()}`;
      setStatus('Dashboard JSON ready', 'ok');
    } else {
      meta.textContent = 'Could not load a backup yet — interact with the dashboard in this tab, then try again. If it stays empty, open Advanced → copy diagnostics report.';
      setStatus('No dashboard JSON found yet', 'err');
      const nn = TEP_DASH_NONJSON_200.length;
      if (nn > 0 && nn !== dashNonJsonHintLastLoggedCount) {
        dashNonJsonHintLastLoggedCount = nn;
        log(`Sniff recorded ${nn} HTTP 200 response(s) on tracked paths (/ajax/ or /namespace/dash-api) whose bodies were not JSON — see Copy troubleshooting report, section "200 non-JSON".`, 'tep-log-info');
      }
    }
    refreshDashboardJsonSummary('backup');
  }

  /** Safe file stem from dashboard title/name (ASCII-first; falls back to "dashboard"). */
  function slugifyDashboardBackupStem(rawTitle, maxLen) {
    const max = maxLen == null ? 72 : maxLen;
    if (rawTitle == null) return '';
    let s = String(rawTitle).trim();
    if (!s) return '';
    s = s.replace(/[\\/<>|":*?]+/g, '').replace(/\s+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '');
    if (s.length > max) s = s.slice(0, max).replace(/-+$/g, '');
    let slug = s.toLowerCase().replace(/[^a-z0-9.-]+/g, '-').replace(/-+/g, '-').replace(/^-+|-+$/g, '');
    if (!slug) slug = 'dashboard';
    return slug;
  }

  function suggestDashboardBackupFileNames() {
    const d = new Date().toISOString().slice(0, 10);
    const ta = root.querySelector('#tep-dash-json');
    let stem = '';
    if (ta && ta.value.trim()) {
      try {
        const norm = normalizeDashRestoreRoot(JSON.parse(ta.value.trim()));
        if (norm && typeof norm === 'object') {
          const rawTitle = norm.title != null ? String(norm.title) : (norm.name != null ? String(norm.name) : '');
          stem = slugifyDashboardBackupStem(rawTitle, 72);
        }
      } catch (_) { /* ignore */ }
    }
    if (!stem) stem = 'dashboard';
    const list = [stem + '-' + d + '.json', stem + '-' + d + '-copy.json', 'te-dashboard-backup-' + d + '.json'];
    return list;
  }

  function downloadDashboardBackup() {
    const ta = root.querySelector('#tep-dash-json');
    if (!ta || !ta.value.trim()) {
      toast('Nothing to save — load a backup into the box first', 'err');
      return;
    }
    const suggestions = suggestDashboardBackupFileNames();
    const defaultName = suggestions[0];
    const msg = 'File name (.json). Suggested names:\n' + suggestions.map((s) => '  · ' + s).join('\n');
    const entered = window.prompt(msg, defaultName);
    if (entered === null) return;
    let name = String(entered).trim();
    if (!name) return;
    name = name.replace(/[\\/<>|":*?]+/g, '-').replace(/\.\.+/g, '.');
    if (!/\.json$/i.test(name)) name += name.endsWith('.') ? 'json' : '.json';
    const blob = new Blob([ta.value], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
    toast('Download started', 'ok');
  }

  function dashboardCatalogDisplayTitle(entry) {
    if (!entry || typeof entry !== 'object') return '(untitled)';
    const d = entry.dashboard && typeof entry.dashboard === 'object' ? entry.dashboard : null;
    const t = entry.title ?? entry.name ?? entry.dashboardTitle ?? entry.label
      ?? (d && (d.title ?? d.name));
    const s = t != null ? String(t).trim() : '';
    return s || '(untitled)';
  }

  /** Best-effort modified/created time in ms for dashboard list rows (unknown → 0). */
  function getDashboardRowSortTimeMs(el) {
    if (!el || typeof el !== 'object' || Array.isArray(el)) return 0;
    const keys = [
      'modifiedDate', 'modifiedTime', 'lastModified', 'updatedAt', 'updatedDate',
      'createdDate', 'createdAt', 'dashboardModifiedDate', 'dateModified', 'lastUpdated',
      'changeDate', 'timestamp'
    ];
    for (const k of keys) {
      const v = el[k];
      if (v == null) continue;
      if (typeof v === 'number' && !Number.isNaN(v)) {
        if (v > 1e12) return v;
        if (v > 1e9 && v < 1e12) return v * 1000;
      }
      const parsed = Date.parse(String(v).trim());
      if (!Number.isNaN(parsed)) return parsed;
    }
    const d = el.dashboard && typeof el.dashboard === 'object' ? el.dashboard : null;
    if (d) {
      const inner = getDashboardRowSortTimeMs(d);
      if (inner) return inner;
    }
    return 0;
  }

  /**
   * Collect dashboard rows from list or aggregate JSON (namespace dash-api, /ajax/dashboards, etc.).
   * Skips obvious in-widget panel objects (widgets array without full dashboard shape).
   */
  function extractDashboardCatalogRows(data) {
    const map = new Map();
    function addRow(el) {
      if (!el || typeof el !== 'object' || Array.isArray(el)) return;
      const id = getPayloadDashboardId(el);
      if (!id || !String(id).trim()) return;
      const sid = String(id).trim();
      const full = looksLikeTeDashboardShape(el);
      const explicitListId = el.dashboardId != null || el.dashboard_id != null;
      const named = (typeof el.title === 'string' && el.title.trim())
        || (typeof el.name === 'string' && el.name.trim())
        || (typeof el.dashboardTitle === 'string' && el.dashboardTitle.trim());
      if (!full && !explicitListId && !named) return;
      if (!full && Array.isArray(el.widgets) && el.widgets.length && !el.template) return;
      const title = dashboardCatalogDisplayTitle(el);
      const modifiedMs = getDashboardRowSortTimeMs(el);
      if (!map.has(sid)) {
        map.set(sid, { title, modifiedMs });
      } else {
        const p = map.get(sid);
        map.set(sid, {
          title: p.title === '(untitled)' && title !== '(untitled)' ? title : p.title,
          modifiedMs: Math.max(p.modifiedMs || 0, modifiedMs || 0)
        });
      }
    }
    function visit(node, depth) {
      if (depth > 14 || node == null) return;
      if (Array.isArray(node)) {
        for (let i = 0; i < node.length; i++) visit(node[i], depth + 1);
        return;
      }
      if (typeof node !== 'object') return;
      addRow(node);
      for (const k of Object.keys(node)) visit(node[k], depth + 1);
    }
    visit(data, 0);
    return [...map.entries()].map(([id, v]) => ({ id, title: v.title, modifiedMs: v.modifiedMs || 0 }));
  }

  async function fetchDashboardCatalogForCleanup() {
    await ensureCurrentAidForDashboard();
    const aid = teInitData && teInitData._currentAid != null ? String(teInitData._currentAid) : '';
    const urls = [
      withAidQuery('/namespace/dash-api/dashboard', aid),
      withAidQuery('/ajax/dashboards', aid),
      withAidQuery('/ajax/user/dashboards', aid),
      withAidQuery('/ajax/settings/dashboards', aid)
    ];
    const merged = new Map();
    for (const url of urls) {
      try {
        const resp = await ajax(url, { method: 'GET' });
        const text = await resp.text();
        const data = tryParseJsonText(text);
        if (!resp.ok || data == null) {
          log(`Dashboard cleanup list: ${url} → HTTP ${resp.status}` + (data == null && text ? ` (${classifyNonJsonAjaxBody(text).slice(0, 80)})` : ''), 'tep-log-info');
          continue;
        }
        const rows = extractDashboardCatalogRows(data);
        for (const r of rows) {
          if (!r.id) continue;
          const ms = typeof r.modifiedMs === 'number' ? r.modifiedMs : 0;
          if (!merged.has(r.id)) {
            merged.set(r.id, { title: r.title, modifiedMs: ms });
          } else {
            const p = merged.get(r.id);
            merged.set(r.id, {
              title: p.title === '(untitled)' && r.title !== '(untitled)' ? r.title : p.title,
              modifiedMs: Math.max(p.modifiedMs || 0, ms)
            });
          }
        }
        if (rows.length) log(`Dashboard cleanup list: ${url} → ${rows.length} row(s)`, 'tep-log-ok');
      } catch (e) {
        log(`Dashboard cleanup list: ${url} → ${e.message}`, 'tep-log-err');
      }
    }
    return [...merged.entries()].map(([id, v]) => ({ id, title: v.title, modifiedMs: v.modifiedMs || 0 }));
  }

  async function tryDeleteDashboardById(dashboardId) {
    const aid = teInitData && teInitData._currentAid != null ? String(teInitData._currentAid) : '';
    const idEnc = encodeURIComponent(dashboardId);
    const attempts = [
      ['DELETE', withAidQuery(`/namespace/dash-api/dashboard/${idEnc}`, aid)],
      ['DELETE', withAidQuery(`/namespace/dash-api/dashboard?dashboardId=${idEnc}`, aid)],
      ['DELETE', withAidQuery(`/ajax/dashboards/${idEnc}`, aid)],
      ['DELETE', withAidQuery(`/ajax/dashboard/${idEnc}`, aid)]
    ];
    for (const [method, url] of attempts) {
      try {
        const resp = await ajax(url, { method });
        const text = await resp.text();
        if (resp.ok) return { ok: true, method, url, status: resp.status, body: text.slice(0, 200) };
        log(`Dashboard delete ${method} ${url} → ${resp.status} ${text.slice(0, 180)}`, 'tep-log-info');
      } catch (e) {
        log(`Dashboard delete → ${e.message}`, 'tep-log-err');
      }
    }
    return { ok: false };
  }

  function setDashCleanupUiBusy(busy) {
    const ids = ['tep-dash-cleanup-refresh', 'tep-dash-cleanup-sort', 'tep-dash-cleanup-delete', 'tep-dash-cleanup-select-none'];
    for (const id of ids) {
      const el = root.querySelector('#' + id);
      if (el) el.disabled = !!busy;
    }
    root.querySelectorAll('.tep-dash-cleanup-cb').forEach((cb) => { cb.disabled = !!busy; });
  }

  function updateDashCleanupSortButton() {
    const btn = root.querySelector('#tep-dash-cleanup-sort');
    if (!btn) return;
    btn.textContent = dashCleanupSortNewestFirst ? 'Sort: newest first' : 'Sort: oldest first';
  }

  function applyDashCleanupSortOrder() {
    dashCleanupCatalog.sort((a, b) => {
      const ta = typeof a.modifiedMs === 'number' ? a.modifiedMs : 0;
      const tb = typeof b.modifiedMs === 'number' ? b.modifiedMs : 0;
      if (ta !== tb) return dashCleanupSortNewestFirst ? (tb - ta) : (ta - tb);
      return String(a.title).localeCompare(String(b.title), undefined, { sensitivity: 'base' });
    });
  }

  function toggleDashCleanupSortOrder() {
    const checked = new Set(
      [...root.querySelectorAll('.tep-dash-cleanup-cb:checked')].map((b) => b.dataset.dashCleanupId).filter(Boolean)
    );
    dashCleanupSortNewestFirst = !dashCleanupSortNewestFirst;
    updateDashCleanupSortButton();
    applyDashCleanupSortOrder();
    renderDashCleanupList();
    for (const cb of root.querySelectorAll('.tep-dash-cleanup-cb')) {
      const id = cb.dataset.dashCleanupId;
      if (id && checked.has(id)) cb.checked = true;
    }
  }

  function renderDashCleanupList() {
    const host = root.querySelector('#tep-dash-cleanup-list');
    if (!host) return;
    host.textContent = '';
    if (!dashCleanupListEverLoaded) {
      const span = document.createElement('span');
      span.className = 'tep-log-info';
      span.style.display = 'block';
      span.style.padding = '10px 12px';
      span.textContent = 'Use “Load dashboards in account group” to fetch names and ids for this account group.';
      host.appendChild(span);
      return;
    }
    if (!dashCleanupCatalog.length) {
      const span = document.createElement('span');
      span.className = 'tep-log-info';
      span.style.display = 'block';
      span.style.padding = '10px 12px';
      span.textContent = 'No dashboards in the merged list — try again after using the Dashboards UI in TE, or check the log for HTTP errors.';
      host.appendChild(span);
      return;
    }
    for (const row of dashCleanupCatalog) {
      const wrap = document.createElement('div');
      wrap.className = 'tep-dash-cleanup-row';
      const label = document.createElement('label');
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'tep-dash-cleanup-cb';
      cb.dataset.dashCleanupId = row.id;
      const textCol = document.createElement('div');
      textCol.className = 'tep-dash-cleanup-titles';
      const nameEl = document.createElement('span');
      nameEl.className = 'tep-dash-cleanup-name';
      nameEl.textContent = row.title;
      const idEl = document.createElement('span');
      idEl.className = 'tep-dash-cleanup-id';
      idEl.textContent = row.id;
      textCol.appendChild(nameEl);
      textCol.appendChild(idEl);
      label.appendChild(cb);
      label.appendChild(textCol);
      wrap.appendChild(label);
      host.appendChild(wrap);
    }
  }

  function syncDashCleanupMeta() {
    const meta = root.querySelector('#tep-dash-cleanup-meta');
    if (!meta) return;
    const aid = teInitData && teInitData._currentAid != null ? String(teInitData._currentAid) : '(unknown)';
    if (!dashCleanupListEverLoaded) {
      meta.textContent = 'Not loaded yet · account group aid is sent as ?aid= when known.';
      return;
    }
    meta.textContent = `${dashCleanupCatalog.length} dashboard(s) in list · aid=${aid}`;
  }

  async function refreshDashboardCleanupList() {
    const meta = root.querySelector('#tep-dash-cleanup-meta');
    if (!teInitData) {
      toast('Session not ready — use Retry Auth', 'err');
      return;
    }
    setDashCleanupUiBusy(true);
    if (meta) meta.textContent = 'Loading dashboard list…';
    try {
      dashCleanupCatalog = await fetchDashboardCatalogForCleanup();
      dashCleanupListEverLoaded = true;
      applyDashCleanupSortOrder();
      syncDashCleanupMeta();
      updateDashCleanupSortButton();
      renderDashCleanupList();
      if (dashCleanupCatalog.length) toast(`Loaded ${dashCleanupCatalog.length} dashboard(s)`, 'ok');
      else toast('No dashboards found — check log', 'err');
    } catch (e) {
      dashCleanupListEverLoaded = true;
      if (meta) meta.textContent = 'Load failed — see log.';
      log('Dashboard cleanup list: ' + e.message, 'tep-log-err');
      toast('Failed to load dashboard list', 'err');
    } finally {
      setDashCleanupUiBusy(false);
    }
  }

  async function bulkDeleteSelectedDashboards() {
    const boxes = [...root.querySelectorAll('.tep-dash-cleanup-cb:checked')];
    const selectedIds = boxes.map((b) => b.dataset.dashCleanupId).filter(Boolean);
    if (!selectedIds.length) {
      toast('Check one or more dashboards to delete', 'err');
      return;
    }
    const lines = selectedIds.map((id) => {
      const row = dashCleanupCatalog.find((r) => r.id === id);
      return ' · ' + (row ? row.title + ' — ' + id : id);
    });
    const preview = lines.length > 18 ? lines.slice(0, 18).join('\n') + '\n · … and ' + (lines.length - 18) + ' more' : lines.join('\n');
    const msg = 'Permanently delete ' + selectedIds.length + ' dashboard(s) from ThousandEyes? This cannot be undone.\n\n' + preview;
    if (!window.confirm(msg)) return;
    setDashCleanupUiBusy(true);
    let ok = 0;
    let fail = 0;
    for (const id of selectedIds) {
      const r = await tryDeleteDashboardById(id);
      if (r.ok) {
        ok++;
        log(`Dashboard deleted: ${id}`, 'tep-log-ok');
        dashCleanupCatalog = dashCleanupCatalog.filter((row) => row.id !== id);
      } else {
        fail++;
        log(`Dashboard delete failed: ${id}`, 'tep-log-err');
      }
    }
    setDashCleanupUiBusy(false);
    syncDashCleanupMeta();
    renderDashCleanupList();
    toast(`Delete finished: ${ok} removed, ${fail} failed`, fail ? 'err' : 'ok');
  }

  function cloneJsonDeep(obj) {
    try {
      return JSON.parse(JSON.stringify(obj));
    } catch (_) {
      return null;
    }
  }

  /** TE ViewDashboard is one object; unwrap [[[{...}]]] or [{...}] to an object. */
  function unwrapIfSingleElementArray(data) {
    let v = data;
    while (Array.isArray(v) && v.length === 1 && v[0] != null && typeof v[0] === 'object') {
      v = v[0];
    }
    return v;
  }

  function looksLikeTeDashboardShape(o) {
    if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
    if (o.template != null && typeof o.template === 'object') return true;
    if (Array.isArray(o.widgets)) return true;
    if (typeof o.title === 'string' && (o.template != null || o.defaultTimespan != null)) return true;
    return false;
  }

  function pickDashboardFromArray(arr) {
    if (!Array.isArray(arr) || !arr.length) return null;
    const hit = arr.find((x) => looksLikeTeDashboardShape(x));
    if (hit) return hit;
    const first = arr[0];
    if (first && typeof first === 'object' && !Array.isArray(first)) return first;
    return null;
  }

  /** Turn pasted/saved backup into one dashboard object for POST ViewDashboard. */
  function normalizeDashRestoreRoot(raw, depth) {
    if (depth == null) depth = 0;
    if (depth > 10) return null;
    let v = cloneJsonDeep(raw);
    if (v == null) return null;
    v = unwrapIfSingleElementArray(v);
    if (Array.isArray(v)) {
      const picked = pickDashboardFromArray(v);
      if (!picked) return null;
      return normalizeDashRestoreRoot(picked, depth + 1);
    }
    if (typeof v !== 'object') return null;
    if (v.data != null) {
      const d = v.data;
      if (Array.isArray(d)) {
        const picked = pickDashboardFromArray(d);
        if (picked) return normalizeDashRestoreRoot(picked, depth + 1);
      } else if (typeof d === 'object' && !Array.isArray(d)) {
        return normalizeDashRestoreRoot(d, depth + 1);
      }
    }
    if (v.result != null && typeof v.result === 'object') {
      return normalizeDashRestoreRoot(v.result, depth + 1);
    }
    for (const key of ['dashboard', 'payload', 'view', 'model']) {
      const inner = v[key];
      if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
        return normalizeDashRestoreRoot(inner, depth + 1);
      }
    }
    for (const key of ['dashboards', 'items', 'results', 'content', 'records']) {
      const arr = v[key];
      if (Array.isArray(arr) && arr.length) {
        const picked = pickDashboardFromArray(arr);
        if (picked) return normalizeDashRestoreRoot(picked, depth + 1);
      }
    }
    return v;
  }

  /**
   * TE dashboards often store layout under `template.widgets` (not root `widgets`).
   * Returns the top-level widget array for walking.
   */
  function getDashboardWidgetsRootArray(dash) {
    if (!dash || typeof dash !== 'object' || Array.isArray(dash)) return [];
    if (Array.isArray(dash.widgets)) return dash.widgets;
    if (dash.template && typeof dash.template === 'object' && Array.isArray(dash.template.widgets)) {
      return dash.template.widgets;
    }
    return [];
  }

  /** Subtitle for a leaf panel (metric code, config title, type, etc.). */
  function inferLeafPanelDetailLabel(node) {
    if (!node || typeof node !== 'object') return '';
    const cfg = node.config;
    if (cfg && typeof cfg === 'object') {
      if (typeof cfg.metric === 'string' && cfg.metric.trim()) return cfg.metric.trim();
      if (cfg.title != null && String(cfg.title).trim()) return String(cfg.title).trim();
      if (cfg.name != null && String(cfg.name).trim()) return String(cfg.name).trim();
    }
    const vc = node.viewConfig;
    if (vc && typeof vc === 'object' && vc.title != null && String(vc.title).trim()) {
      return String(vc.title).trim();
    }
    if (node.meta && typeof node.meta === 'object') {
      const d = node.meta.description != null && String(node.meta.description).trim();
      if (d) return d.length > 96 ? d.slice(0, 96) + '…' : d;
    }
    return String(node.type || node.widgetType || '').trim();
  }

  /**
   * Leaf panels with a display label: ancestor `meta.title` (section) + leaf detail (e.g. NAS metric).
   * Matches TE exports where tiles have no `title` but sit under a titled group row.
   */
  function flattenDashboardPanelEntries(dash) {
    const out = [];
    function walk(node, sectionTitle) {
      if (!node || typeof node !== 'object') return;
      let nextSection = sectionTitle && String(sectionTitle).trim() ? String(sectionTitle).trim() : '';
      const meta = node.meta;
      if (meta && typeof meta === 'object') {
        const mt = meta.title != null && String(meta.title).trim();
        if (mt) nextSection = String(meta.title).trim();
      }
      if (!nextSection && node.title != null && String(node.title).trim()) {
        nextSection = String(node.title).trim();
      }
      if (!nextSection && node.name != null && String(node.name).trim()) {
        nextSection = String(node.name).trim();
      }
      const nested = Array.isArray(node.widgets) ? node.widgets : null;
      if (nested && nested.length) {
        for (let i = 0; i < nested.length; i++) walk(nested[i], nextSection);
        return;
      }
      const detail = inferLeafPanelDetailLabel(node);
      let displayName = '';
      if (nextSection && detail) displayName = nextSection + ' · ' + detail;
      else displayName = nextSection || detail;
      if (!displayName) {
        const typ = String(node.type || 'panel').trim();
        const tid = node.widgetId != null ? String(node.widgetId) : '';
        displayName = typ + (tid ? ' · id ' + tid : '');
      }
      out.push({ node, displayName });
    }
    const roots = getDashboardWidgetsRootArray(dash);
    for (let i = 0; i < roots.length; i++) walk(roots[i], '');
    return out;
  }

  /**
   * Leaf widget nodes only (deepest panels). Parent rows with nested `widgets[]` are skipped;
   * children are visited depth-first — matches TE “numbers” groups with inner tiles.
   */
  function flattenDashboardWidgetsForRestore(dash) {
    return flattenDashboardPanelEntries(dash).map((e) => e.node);
  }

  /** Update collapsed summary line for backup or restore JSON (valid / invalid / empty). */
  function refreshDashboardJsonSummary(which) {
    const isBackup = which === 'backup';
    const ta = root.querySelector(isBackup ? '#tep-dash-json' : '#tep-dash-restore-json');
    const sumEl = root.querySelector(isBackup ? '#tep-dash-json-summary' : '#tep-dash-restore-json-summary');
    if (!ta || !sumEl) return;
    const raw = ta.value;
    const trimmed = raw.trim();
    if (!trimmed) {
      sumEl.textContent = isBackup
        ? 'No JSON yet — expand to edit'
        : 'No JSON yet — expand to paste or use Open import file…';
      sumEl.className = 'tep-dash-json-sum tep-dash-json-sum-empty';
      return;
    }
    let parsed;
    try {
      parsed = JSON.parse(trimmed);
    } catch (e) {
      const msg = (e && e.message) ? String(e.message) : 'parse error';
      sumEl.textContent = 'Invalid JSON — expand to fix · ' + msg.slice(0, 96);
      sumEl.className = 'tep-dash-json-sum tep-dash-json-sum-err';
      return;
    }
    let bytes = raw.length;
    try {
      bytes = new Blob([raw]).size;
    } catch (_) { /* */ }
    const sizeLabel = bytes >= 1024 ? (bytes / 1024).toFixed(1) + ' KB' : bytes + ' B';
    let sub = '';
    try {
      const norm = normalizeDashRestoreRoot(parsed);
      if (norm && typeof norm === 'object' && !Array.isArray(norm)) {
        const t = norm.title != null ? String(norm.title) : (norm.name != null ? String(norm.name) : '');
        const panelCount = flattenDashboardWidgetsForRestore(norm).length;
        const topRows = getDashboardWidgetsRootArray(norm).length;
        const id = norm.dashboardId ?? norm.dashboard_id ?? norm.id;
        const bits = [];
        if (t) bits.push('title: "' + t.replace(/"/g, '\'').slice(0, 56) + (t.length > 56 ? '…' : '') + '"');
        if (panelCount) bits.push(panelCount + ' panel' + (panelCount === 1 ? '' : 's'));
        else if (topRows) bits.push(topRows + ' top-level row' + (topRows === 1 ? '' : 's'));
        if (id != null && String(id) !== '') bits.push('id ' + String(id).slice(0, 16));
        sub = bits.length ? bits.join(' · ') : 'dashboard-shaped object';
      } else if (Array.isArray(parsed)) {
        sub = 'JSON array[' + parsed.length + '] (restore expects one dashboard object)';
      } else if (parsed != null && typeof parsed === 'object') {
        const keys = Object.keys(parsed);
        sub = 'object — keys: ' + keys.slice(0, 10).join(', ') + (keys.length > 10 ? '…' : '') + ' (not a recognized dashboard root)';
      } else {
        sub = 'JSON ' + typeof parsed;
      }
    } catch (_) {
      sub = (parsed != null && typeof parsed === 'object') ? topLevelKeysLabel(parsed) : String(typeof parsed);
    }
    sumEl.textContent = 'Valid JSON · ' + sizeLabel + ' · ' + sub;
    sumEl.className = 'tep-dash-json-sum tep-dash-json-sum-ok';
  }

  /**
   * TE POST /namespace/dash-api/dashboard returns 400 "Dashboard already has an id." if the JSON body
   * still carries root id fields — the dashboard id for updates must be only in ?dashboardId=.
   */
  function stripRootIdsForDashNamespacePost(obj) {
    const o = cloneJsonDeep(obj);
    if (!o || typeof o !== 'object' || Array.isArray(o)) return null;
    delete o.dashboardId;
    delete o.dashboard_id;
    delete o.id;
    delete o._id;
    delete o.mongoId;
    return o;
  }

  function buildDashRestorePayloadCandidates(normObj) {
    const out = [];
    const pushUniq = (obj) => {
      if (obj == null) return;
      const s = JSON.stringify(obj);
      if (s && out.indexOf(s) < 0) out.push(s);
    };
    if (!normObj || typeof normObj !== 'object' || Array.isArray(normObj)) return out;
    pushUniq(stripRootIdsForDashNamespacePost(normObj));
    if (normObj.dashboard && typeof normObj.dashboard === 'object' && normObj.template == null && normObj.title == null) {
      pushUniq(stripRootIdsForDashNamespacePost(normObj.dashboard));
    }
    return out;
  }

  const DASH_RESTORE_NAME_CONFLICT_MAX = 24;

  function isLikelyDuplicateDashNameError(status, text) {
    if (status !== 400 && status !== 409 && status !== 422) return false;
    const j = tryParseJsonText(text || '');
    const parts = [];
    if (j && typeof j === 'object') {
      if (j.message != null) parts.push(String(j.message));
      if (j.error != null) parts.push(String(j.error));
      if (j.detail != null) parts.push(String(j.detail));
    }
    parts.push(String(text || '').slice(0, 900));
    const s = parts.join(' ').toLowerCase();
    if (/already\s+exists?|already\s+exist|duplicate|unique|name\s+taken|conflict|same\s+(name|title)/i.test(s)) return true;
    if (s.includes('name') && (s.includes('exist') || s.includes('taken') || s.includes('use'))) return true;
    if (s.includes('title') && (s.includes('exist') || s.includes('taken') || s.includes('duplicate'))) return true;
    return false;
  }

  function bumpDashboardTitleField(obj) {
    const c = cloneJsonDeep(obj);
    if (!c || typeof c !== 'object' || Array.isArray(c)) return obj;
    const field = typeof c.title === 'string' ? 'title' : (typeof c.name === 'string' ? 'name' : null);
    if (!field) {
      c.title = 'Dashboard (2)';
      return c;
    }
    const t = String(c[field]);
    const m = t.match(/^(.+?)\s*\((\d+)\)\s*$/);
    if (m) {
      const n = parseInt(m[2], 10);
      c[field] = `${m[1].trim()} (${Number.isFinite(n) ? n + 1 : 2})`;
    } else {
      c[field] = `${t} (2)`;
    }
    return c;
  }

  function normalizeDashboardVAgentIdList(ids) {
    return (ids || []).map((x) => (typeof x === 'number' ? x : (Number.isFinite(Number(x)) ? Number(x) : x)));
  }

  /** Checkbox Set may not match portal `agents[].agentId` if one side is string vs number. */
  function restoreAgentSelectionSetHas(set, agentId) {
    if (!set || agentId == null) return false;
    if (set.has(agentId)) return true;
    const s = String(agentId);
    if (set.has(s)) return true;
    const n = Number(agentId);
    if (Number.isFinite(n) && set.has(n)) return true;
    return false;
  }

  function addAgentIdToSelectionSet(set, agentId) {
    if (!set || agentId == null) return;
    set.add(agentId);
    set.add(String(agentId));
    const n = Number(agentId);
    if (Number.isFinite(n)) set.add(n);
  }

  function removeAgentIdFromSelectionSet(set, agentId) {
    if (!set || agentId == null) return;
    set.delete(agentId);
    set.delete(String(agentId));
    const n = Number(agentId);
    if (Number.isFinite(n)) set.delete(n);
  }

  /** Rewrite vAgentIds / agentSet / agentIds under obj (recursive). ids=[] clears; non-empty replaces every matching array. */
  function rewriteAllVAgentLikeArrays(obj, ids, depth) {
    if (depth == null) depth = 0;
    if (depth > 28 || obj == null || typeof obj !== 'object') return;
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) rewriteAllVAgentLikeArrays(obj[i], ids, depth + 1);
      return;
    }
    const has = Array.isArray(ids) && ids.length > 0;
    const list = () => normalizeDashboardVAgentIdList(ids);
    if (Array.isArray(obj.vAgentIds)) obj.vAgentIds = has ? list() : [];
    if (Array.isArray(obj.agentIds)) obj.agentIds = has ? list() : [];
    if (Array.isArray(obj.physicalAgentIds)) obj.physicalAgentIds = [];
    if (obj.agentSet && typeof obj.agentSet === 'object') {
      if (Array.isArray(obj.agentSet.vAgentIds)) obj.agentSet.vAgentIds = has ? list() : [];
      if (Array.isArray(obj.agentSet.agentIds)) obj.agentSet.agentIds = has ? list() : [];
      if (Array.isArray(obj.agentSet.agents)) obj.agentSet.agents = [];
    }
    if (Array.isArray(obj.agents) && obj.agents.length && typeof obj.agents[0] === 'object') obj.agents = [];
    for (const k of Object.keys(obj)) rewriteAllVAgentLikeArrays(obj[k], ids, depth + 1);
  }

  /** Walk the full dashboard JSON and delete every own `filters` property (widget map or array form). */
  function stripAllWidgetFiltersFromDashboardJson(obj, depth) {
    if (depth == null) depth = 0;
    if (depth > 42 || obj === null || typeof obj !== 'object') return;
    if (Array.isArray(obj)) {
      for (let i = 0; i < obj.length; i++) stripAllWidgetFiltersFromDashboardJson(obj[i], depth + 1);
      return;
    }
    if (Object.prototype.hasOwnProperty.call(obj, 'filters')) delete obj.filters;
    for (const k of Object.keys(obj)) stripAllWidgetFiltersFromDashboardJson(obj[k], depth + 1);
  }

  function applyDashRestoreTitle(dash, titleTrim) {
    if (!dash || typeof dash !== 'object' || !titleTrim) return;
    if (typeof dash.title === 'string') dash.title = titleTrim;
    else if (typeof dash.name === 'string') dash.name = titleTrim;
    else dash.title = titleTrim;
  }

  function applyDashRestoreAgentOptions(dash, opts) {
    const mode = opts && opts.mode ? opts.mode : 'keep';
    if (!dash || typeof dash !== 'object' || mode === 'keep') return;
    if (mode === 'strip') {
      rewriteAllVAgentLikeArrays(dash, [], 0);
      stripAllWidgetFiltersFromDashboardJson(dash, 0);
    }
  }

  function syncDashRestoreAgentUi() {
    const modeEl = root.querySelector('#tep-dash-restore-agent-mode');
    const wrap = root.querySelector('#tep-dash-restore-agents-wrap');
    const note = root.querySelector('#tep-dash-restore-agent-note');
    if (!modeEl || !wrap) return;
    const mode = modeEl.value;
    const show = mode === 'strip';
    wrap.style.display = show ? '' : 'none';
    if (note && mode === 'strip') {
      note.textContent = 'All widget `filters` keys are removed from the JSON, and virtual-agent fields are cleared.';
    }
  }

  async function restoreDashboardFromEditor() {
    const ta = root.querySelector('#tep-dash-restore-json');
    if (!ta || !ta.value.trim()) {
      toast('Import or paste dashboard JSON on the Restore tab first', 'err');
      return;
    }
    const titleEl = root.querySelector('#tep-dash-restore-title');
    const titleTrim = titleEl && titleEl.value ? titleEl.value.trim() : '';
    const modeEl = root.querySelector('#tep-dash-restore-agent-mode');
    const mode = (modeEl && modeEl.value) || 'keep';
    let body;
    try {
      body = JSON.parse(ta.value);
    } catch (e) {
      toast('Invalid JSON: ' + e.message, 'err');
      return;
    }
    const normRaw = normalizeDashRestoreRoot(body);
    if (!normRaw) {
      const hint = Array.isArray(body)
        ? `root is Array(len=${body.length})`
        : (body && typeof body === 'object' ? `root keys: ${Object.keys(body).slice(0, 12).join(', ')}` : String(typeof body));
      toast('Could not find one dashboard object in JSON (nested arrays / wrappers). See log for shape hint.', 'err');
      log('Restore: normalizeDashRestoreRoot failed — ' + hint + '. Paste GET /namespace/dash-api/dashboard body or unwrap to { title, template, … }.', 'tep-log-err');
      return;
    }
    let confirmMsg = 'Restore this backup to ThousandEyes? ';
    if (titleTrim) confirmMsg += `Title: “${titleTrim}”. `;
    if (mode === 'strip') confirmMsg += 'All widget filters removed and virtual-agent fields cleared in the JSON. ';
    else confirmMsg += 'Agents and filters: left as in the backup. ';
    confirmMsg += 'Continue?';
    if (!confirm(confirmMsg)) return;
    const norm = cloneJsonDeep(normRaw);
    if (titleTrim) applyDashRestoreTitle(norm, titleTrim);
    applyDashRestoreAgentOptions(norm, { mode });
    log(`Restore: applying options — mode=${mode}` + (titleTrim ? `, title override` : ''), 'tep-log-info');

    const aid = teInitData && teInitData._currentAid != null ? String(teInitData._currentAid) : '';
    const fromBody = norm.dashboardId ?? norm.dashboard_id ?? norm.id;
    const id = fromBody != null && String(fromBody) !== '' ? String(fromBody) : null;
    const locId = extractDashboardIdFromLocation();

    const payloadCandidates = buildDashRestorePayloadCandidates(norm);
    if (!payloadCandidates.length) {
      toast('Could not build restore payload', 'err');
      return;
    }

    const namespaceAttempts = [];
    if (id) {
      namespaceAttempts.push(['POST', withAidQuery(`/namespace/dash-api/dashboard/${encodeURIComponent(id)}`, aid)]);
      namespaceAttempts.push(['POST', withAidQuery(`/namespace/dash-api/dashboard?dashboardId=${encodeURIComponent(id)}`, aid)]);
    }
    if (locId && locId !== id) {
      namespaceAttempts.push(['POST', withAidQuery(`/namespace/dash-api/dashboard/${encodeURIComponent(locId)}`, aid)]);
      namespaceAttempts.push(['POST', withAidQuery(`/namespace/dash-api/dashboard?dashboardId=${encodeURIComponent(locId)}`, aid)]);
    }
    namespaceAttempts.push(['POST', withAidQuery('/namespace/dash-api/dashboard', aid)]);

    for (const [method, url] of namespaceAttempts) {
      for (const initialPayload of payloadCandidates) {
        let obj;
        try {
          obj = JSON.parse(initialPayload);
        } catch (_) {
          log('Restore: skipped invalid payload candidate', 'tep-log-err');
          continue;
        }
        for (let bump = 0; bump <= DASH_RESTORE_NAME_CONFLICT_MAX; bump++) {
          try {
            const payload = JSON.stringify(obj);
            const resp = await ajax(url, { method, body: payload });
            const text = await resp.text();
            if (resp.ok) {
              toast('Restore request accepted', 'ok');
              const label = obj.title != null ? obj.title : (obj.name != null ? obj.name : '');
              log(`Restore OK ${method} ${url}` + (bump ? ` · final title/name: ${label}` : ''), 'tep-log-ok');
              return;
            }
            if (bump < DASH_RESTORE_NAME_CONFLICT_MAX && isLikelyDuplicateDashNameError(resp.status, text)) {
              obj = bumpDashboardTitleField(obj);
              const nextLabel = obj.title != null ? obj.title : (obj.name != null ? obj.name : '');
              log(`Restore: duplicate name/title (${resp.status}) → retry with "${nextLabel}"`, 'tep-log-info');
              continue;
            }
            log(`Restore ${method} ${url} → ${resp.status} ${text.slice(0, 280)}`, 'tep-log-info');
            break;
          } catch (e) {
            log(`Restore ${method} ${url} → ${e.message}`, 'tep-log-err');
            break;
          }
        }
      }
    }

    const ajaxId = id || locId;
    const ajaxAttempts = [];
    if (ajaxId) {
      ajaxAttempts.push(['PUT', withAidQuery(`/ajax/dashboards/${ajaxId}`, aid)]);
      ajaxAttempts.push(['POST', withAidQuery(`/ajax/dashboards/${ajaxId}`, aid)]);
      ajaxAttempts.push(['PUT', withAidQuery(`/ajax/dashboard/${ajaxId}`, aid)]);
      ajaxAttempts.push(['POST', withAidQuery(`/ajax/dashboard/${ajaxId}`, aid)]);
    }
    ajaxAttempts.push(['POST', withAidQuery('/ajax/dashboards', aid)]);
    for (const [method, url] of ajaxAttempts) {
      try {
        const resp = await ajax(url, { method, body: JSON.stringify(norm) });
        const text = await resp.text();
        if (resp.ok) {
          toast('Restore request accepted', 'ok');
          log(`Restore OK ${method} ${url}`, 'tep-log-ok');
          return;
        }
        log(`Restore ${method} ${url} → ${resp.status} ${text.slice(0, 280)}`, 'tep-log-info');
      } catch (e) {
        log(`Restore ${method} ${url} → ${e.message}`, 'tep-log-err');
      }
    }
    toast('Restore failed — see log for TE responses', 'err');
  }

  function stopPersistentIntercept() { /* no-op now */ }

  // ---------------------------------------------------------------------------
  // Main auth flow — uses TE internal /ajax/ API with session cookies
  // ---------------------------------------------------------------------------
  async function initAuth() {
    if (!isOnTEPage()) {
      setStatus('⚠ Not on app.thousandeyes.com — inject this script there', 'err');
      log('This script must run on app.thousandeyes.com.', 'tep-log-err');
      return;
    }

    const csrf = detectCsrfToken();
    if (csrf) csrfToken = csrf;

    setStatus('Verifying session via internal API…');
    log('Calling /ajax/settings/tests/init to verify session…', 'tep-log-info');

    try {
      const resp = await ajax('/ajax/settings/tests/init?includeTeConfig=false');
      if (!resp.ok) {
        setStatus(`Session check failed (${resp.status}) — are you logged in?`, 'err');
        log(`/ajax/settings/tests/init returned ${resp.status}. Make sure you are logged into ThousandEyes.`, 'tep-log-err');
        return;
      }
      teInitData = await resp.json();
      log('Session verified via internal API.', 'tep-log-ok');

      // Load account groups and populate dropdown
      await loadAccountGroups();

      if (isDashboardToolsPage()) {
        await ensureCurrentAidForDashboard();
        if (teInitData._currentAid != null && teInitData._currentAid !== '') {
          log(`Dashboard mode: using account group aid=${teInitData._currentAid} for API calls.`, 'tep-log-ok');
        } else {
          log('Dashboard mode: aid still unknown — dashboard probes run without ?aid= (may 404).', 'tep-log-err');
        }
        setStatus('Authenticated — dashboard tools', 'ok');
        log('Dashboard mode: session OK; loading portal agents for restore…', 'tep-log-ok');
        try {
          await loadAgents();
        } catch (e) {
          log('Dashboard mode: optional agent load failed — ' + e.message, 'tep-log-info');
        }
        refreshDashboardEditor();
      } else {
        setStatus('Authenticated — loading agents…', 'ok');
        log('Session OK. Loading agents…', 'tep-log-ok');
        loadAgents();
      }
    } catch (e) {
      setStatus('Auth failed — ' + e.message, 'err');
      log('Error: ' + e.message, 'tep-log-err');
    }
  }

  // ---------------------------------------------------------------------------
  // Load account groups and populate dropdown
  // ---------------------------------------------------------------------------
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|;\\s*)' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : null;
  }

  async function loadAccountGroups() {
    // 1. Read teAccount cookie (set by TE when switching account groups)
    const cookieAid = getCookie('teAccount');
    if (cookieAid) {
      teInitData._currentAid = parseInt(cookieAid, 10) || cookieAid;
      log(`Account group from cookie: ${cookieAid}`, 'tep-log-ok');
      return;
    }

    // 2. Fallback: try URL ?aid= parameter
    try {
      const urlAid = new URLSearchParams(window.location.search).get('aid');
      if (urlAid) {
        teInitData._currentAid = parseInt(urlAid, 10) || urlAid;
        log(`Account group from URL: ${urlAid}`, 'tep-log-info');
        return;
      }
    } catch { /* */ }

    log('No teAccount cookie found. Aid will be auto-detected from agents.', 'tep-log-info');
  }

  function inferAidFromTeInitData(data) {
    if (!data || typeof data !== 'object') return null;
    const tryVal = (v) => {
      if (v == null) return null;
      const s = String(v).trim();
      if (/^\d+$/.test(s) && s !== '0') return s;
      return null;
    };
    const direct = [
      data.aid, data.accountAid, data.accountGroupId, data.accountGroupID,
      data.activeAid, data.currentAid, data.defaultAid, data.primaryAid,
      data.organizationAid, data.orgAid
    ];
    for (const v of direct) {
      const t = tryVal(v);
      if (t) return t;
    }
    if (data.user && typeof data.user === 'object') {
      for (const v of [data.user.aid, data.user.accountAid, data.user.defaultAid, data.user.activeAid]) {
        const t = tryVal(v);
        if (t) return t;
      }
    }
    if (data.account && typeof data.account === 'object') {
      for (const v of [data.account.aid, data.account.id, data.account.accountGroupId]) {
        const t = tryVal(v);
        if (t) return t;
      }
    }
    for (const k of Object.keys(data)) {
      if (!/aid|accountgroup|orgid/i.test(k)) continue;
      const t = tryVal(data[k]);
      if (t) return t;
    }
    return null;
  }

  /**
   * Dashboard mode skips loadAgents(), which used to infer _currentAid from virtual-agents.
   * Without aid, many /ajax URLs return HTML 404 shells — resolve aid before dashboard probes.
   */
  async function ensureCurrentAidForDashboard() {
    if (!teInitData || typeof teInitData !== 'object') return;
    if (teInitData._currentAid != null && teInitData._currentAid !== '') return;

    const fromInit = inferAidFromTeInitData(teInitData);
    if (fromInit) {
      teInitData._currentAid = parseInt(fromInit, 10) || fromInit;
      log(`Account group from /ajax/settings/tests/init: ${teInitData._currentAid}`, 'tep-log-ok');
      dashConsole('info', 'resolved aid from init JSON', { aid: teInitData._currentAid });
      return;
    }

    log('Resolving account group via /ajax/settings/tests/virtual-agents (dashboard mode)…', 'tep-log-info');
    try {
      const vResp = await ajax('/ajax/settings/tests/virtual-agents');
      if (!vResp.ok) {
        log(`virtual-agents (aid lookup) → HTTP ${vResp.status}`, 'tep-log-info');
        return;
      }
      const vData = await vResp.json();
      const vAgents = vData.vAgents || vData.virtualAgents || (Array.isArray(vData) ? vData : []);
      if (!vAgents.length) {
        log('virtual-agents: empty; cannot infer aid.', 'tep-log-info');
        return;
      }
      const aidCounts = {};
      for (const a of vAgents) {
        if (a.primaryAid != null) aidCounts[a.primaryAid] = (aidCounts[a.primaryAid] || 0) + 1;
      }
      const sorted = Object.entries(aidCounts).sort((a, b) => b[1] - a[1]);
      if (sorted.length) {
        teInitData._currentAid = parseInt(sorted[0][0], 10) || sorted[0][0];
        log(`Account group auto-detected (virtual-agents): ${teInitData._currentAid}`, 'tep-log-ok');
        dashConsole('info', 'resolved aid from virtual-agents', { aid: teInitData._currentAid });
      } else {
        log('virtual-agents: no primaryAid on agents; cannot infer aid.', 'tep-log-info');
      }
    } catch (e) {
      log('ensureCurrentAidForDashboard: ' + e.message, 'tep-log-err');
    }
  }

  // ---------------------------------------------------------------------------
  // Load agents from TE internal endpoints
  // ---------------------------------------------------------------------------
  async function loadAgents() {
    try {
      agentsBox.innerHTML = '<span class="tep-log-info">Loading agents…</span>';
      agents = [];

      // Fetch agents from /ajax/settings/tests/virtual-agents
      // The vAgents array contains agents assigned to the current account group
      try {
        const vResp = await ajax('/ajax/settings/tests/virtual-agents');
        if (vResp.ok) {
          const vData = await vResp.json();
          const vAgents = vData.vAgents || vData.virtualAgents || (Array.isArray(vData) ? vData : []);

          // Auto-detect current aid from agents if not set
          if (!teInitData._currentAid && vAgents.length) {
            // Find the most common primaryAid among non-cloud agents (those with a primaryAid)
            const aidCounts = {};
            for (const a of vAgents) {
              if (a.primaryAid) aidCounts[a.primaryAid] = (aidCounts[a.primaryAid] || 0) + 1;
            }
            // The current account group's enterprise agents share the same primaryAid
            const sorted = Object.entries(aidCounts).sort((a, b) => b[1] - a[1]);
            if (sorted.length) {
              teInitData._currentAid = parseInt(sorted[0][0], 10) || sorted[0][0];
              log(`Auto-detected account group ID: ${teInitData._currentAid} (${sorted[0][1]} agents)`, 'tep-log-info');
            }
          }

          const activeAid = teInitData._currentAid;
          let enterpriseCount = 0, cloudCount = 0;

          for (const a of vAgents) {
            const isEnterprise = activeAid && a.primaryAid === activeAid;
            if (isEnterprise) enterpriseCount++; else cloudCount++;
            // Build location string from location object or countryId
            let loc = '';
            if (a.location && typeof a.location === 'object') {
              loc = [a.location.city, a.location.state, a.location.country].filter(Boolean).join(', ');
            } else if (typeof a.location === 'string') {
              loc = a.location;
            }
            if (!loc) loc = a.countryId || '';
            agents.push({
              agentId: a.vAgentId || a.agentId || a.id,
              agentName: a.displayName || a.name || ('Agent ' + (a.vAgentId || a.agentId)),
              agentType: isEnterprise ? 'Enterprise' : 'Cloud',
              location: loc,
              status: 'unknown',
              physicalId: a.agentId || a.physicalAgentId || null,
              lastSeen: null
            });
          }
          log(`Loaded ${enterpriseCount} enterprise + ${cloudCount} cloud agent(s).`, 'tep-log-ok');
        }
      } catch (e) { log('Agent load error: ' + e.message, 'tep-log-err'); }

      // Fetch enterprise physical agent status for online/offline
      try {
        const pResp = await ajax('/ajax/settings/tests/physical-agents/enterprise');
        if (pResp.ok) {
          const pData = await pResp.json();
          // Response may be keyed by aid or a flat array
          let physicalAgents = [];
          if (Array.isArray(pData)) {
            physicalAgents = pData;
          } else {
            for (const k of Object.keys(pData)) {
              const v = pData[k];
              if (Array.isArray(v)) physicalAgents.push(...v);
            }
          }

          // Build a map of agentId -> status info
          const statusMap = {};
          for (const pa of physicalAgents) {
            const id = pa.agentId || pa.id;
            if (!id) continue;
            // TE uses agentStatus or status field; "ONLINE" or 1 = online
            const raw = pa.agentStatus || pa.status || pa.agentState || '';
            const isOnline = raw === 'ONLINE' || raw === 'Online' || raw === 1 || raw === true
              || (typeof raw === 'string' && raw.toLowerCase().includes('online'));
            const isOffline = raw === 'OFFLINE' || raw === 'Offline' || raw === 0 || raw === false
              || (typeof raw === 'string' && raw.toLowerCase().includes('offline'));
            statusMap[id] = isOnline ? 'online' : (isOffline ? 'offline' : 'unknown');
            // Also try to map via name or vAgentId
            if (pa.vAgentId) statusMap['v_' + pa.vAgentId] = statusMap[id];
          }

          // Log first physical agent structure for debugging
          if (physicalAgents.length) {
            const sample = physicalAgents[0];
            const statusKeys = Object.keys(sample).filter(k => /status|state|online|last/i.test(k));
            log(`Physical agents: ${physicalAgents.length}, status keys: ${statusKeys.join(', ')} = ${statusKeys.map(k => sample[k]).join(', ')}`, 'tep-log-info');
          }

          // Match physical agent status to virtual agents
          let matched = 0;
          for (const a of agents) {
            if (a.agentType !== 'Enterprise') continue;
            const s = statusMap[a.physicalId] || statusMap['v_' + a.agentId];
            if (s) { a.status = s; matched++; }
          }
          log(`Matched status for ${matched} enterprise agent(s).`, 'tep-log-info');
        }
      } catch (e) { log('Physical agent status error: ' + e.message, 'tep-log-info'); }

      agents.sort((a, b) => {
        // Enterprise first, then by status (online first), then by name
        if (a.agentType !== b.agentType) return a.agentType === 'Enterprise' ? -1 : 1;
        if (a.status !== b.status) {
          if (a.status === 'online') return -1;
          if (b.status === 'online') return 1;
          if (a.status === 'offline') return 1;
          if (b.status === 'offline') return -1;
        }
        return (a.agentName || '').localeCompare(b.agentName || '');
      });
      renderAgents();
      if (isDashboardToolsPage()) {
        setStatus(`Dashboard — ${agents.length} portal agent(s) loaded`, 'ok');
      } else {
        setStatus(`Authenticated — ${agents.length} agent(s) loaded`, 'ok');
      }
    } catch (e) {
      agentsBox.innerHTML = `<span class="tep-log-err">Error: ${e.message}</span>`;
    }
  }

  /**
   * Shared Enterprise / Cloud grouped picker (same pattern as Create Tests).
   * @param {HTMLElement|null} boxEl
   * @param {string} filter
   * @param {Set} selectionSet agentId membership
   * @param {{ emptyText?: string, noAgentsText?: string, focusSection?: 'selected'|'enterprise'|'cloud' }} opts
   */
  function renderAgentPickerSection(boxEl, filter, selectionSet, opts) {
    const options = opts || {};
    if (!boxEl) return;
    const q = (filter || '').toLowerCase();
    if (!agents.length) {
      boxEl.innerHTML = `<span class="tep-log-info">${options.noAgentsText || 'Agents will load after auth…'}</span>`;
      return;
    }
    const filtered = q
      ? agents.filter((a) =>
          (a.agentName || '').toLowerCase().includes(q) ||
          (a.location || '').toLowerCase().includes(q) ||
          (a.agentType || '').toLowerCase().includes(q)
        )
      : agents;

    if (!filtered.length) {
      boxEl.innerHTML = `<span class="tep-log-info">${options.emptyText || 'No agents match filter.'}</span>`;
      return;
    }

    const selectedAgents = filtered.filter((a) => restoreAgentSelectionSetHas(selectionSet, a.agentId));
    const enterprise = filtered.filter(
      (a) => a.agentType === 'Enterprise' && !restoreAgentSelectionSetHas(selectionSet, a.agentId)
    );
    const cloud = filtered.filter(
      (a) => a.agentType !== 'Enterprise' && !restoreAgentSelectionSetHas(selectionSet, a.agentId)
    );

    function sortEnterpriseAgents(list) {
      return [...list].sort((a, b) => {
        if (a.status !== b.status) {
          if (a.status === 'online') return -1;
          if (b.status === 'online') return 1;
          if (a.status === 'offline') return 1;
          if (b.status === 'offline') return -1;
        }
        return (a.agentName || '').localeCompare(b.agentName || '');
      });
    }
    function sortSelectedAgents(list) {
      return [...list].sort((a, b) => {
        const aEnt = a.agentType === 'Enterprise' ? 0 : 1;
        const bEnt = b.agentType === 'Enterprise' ? 0 : 1;
        if (aEnt !== bEnt) return aEnt - bEnt;
        if (a.status !== b.status) {
          if (a.status === 'online') return -1;
          if (b.status === 'online') return 1;
          if (a.status === 'offline') return 1;
          if (b.status === 'offline') return -1;
        }
        return (a.agentName || '').localeCompare(b.agentName || '');
      });
    }
    function sortCloudAgents(list) {
      return [...list].sort((a, b) => (a.agentName || '').localeCompare(b.agentName || ''));
    }

    const selectedSorted = sortSelectedAgents(selectedAgents);
    const enterpriseSorted = sortEnterpriseAgents(enterprise);
    const cloudSorted = sortCloudAgents(cloud);

    function effectiveAgentSectionFocus(cat) {
      if (!cat) return null;
      if (cat === 'selected' && selectedSorted.length) return 'selected';
      if (cat === 'enterprise' && enterpriseSorted.length) return 'enterprise';
      if (cat === 'cloud' && cloudSorted.length) return 'cloud';
      if (selectedSorted.length) return 'selected';
      if (enterpriseSorted.length) return 'enterprise';
      if (cloudSorted.length) return 'cloud';
      return null;
    }
    const eff = effectiveAgentSectionFocus(options.focusSection);

    boxEl.innerHTML = '';

    const renderSection = (sectionKey, title, list, fallbackOpen) => {
      if (!list.length) return;
      const section = document.createElement('div');
      section.className = 'tep-agent-section';
      section.dataset.tepSection = sectionKey;
      section.style.marginBottom = '6px';
      const header = document.createElement('div');
      header.style.cssText = 'font-weight:bold;padding:4px 6px;background:#2a2a2a;border-radius:4px;cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center;';
      const shouldOpen = eff ? eff === sectionKey : fallbackOpen;
      header.innerHTML = `<span>${title} (${list.length})</span><span class="tep-section-arrow">${shouldOpen ? '▼' : '▶'}</span>`;
      const body = document.createElement('div');
      body.className = 'tep-agent-section-body';
      body.style.display = shouldOpen ? '' : 'none';

      header.addEventListener('click', () => {
        const open = body.style.display !== 'none';
        body.style.display = open ? 'none' : '';
        header.querySelector('.tep-section-arrow').textContent = open ? '▶' : '▼';
      });

      list.forEach((agent) => {
        const item = document.createElement('label');
        item.className = 'tep-agent-item';
        const checked = restoreAgentSelectionSetHas(selectionSet, agent.agentId) ? 'checked' : '';
        const statusDot = agent.agentType === 'Enterprise'
          ? `<span class="tep-agent-status ${agent.status}" title="${agent.status}"></span>`
          : '';
        item.innerHTML = `
          <input type="checkbox" value="${agent.agentId}" ${checked}>
          ${statusDot}
          <span class="tep-agent-name">${agent.agentName || 'Agent ' + agent.agentId}</span>
          <span class="tep-agent-loc">${agent.location || ''}</span>
        `;
        const cb = item.querySelector('input');
        cb.addEventListener('change', () => {
          if (cb.checked) addAgentIdToSelectionSet(selectionSet, agent.agentId);
          else removeAgentIdFromSelectionSet(selectionSet, agent.agentId);
          renderAgentPickerSection(boxEl, filter, selectionSet, {
            ...options,
            focusSection: sectionKey
          });
        });
        body.appendChild(item);
      });

      section.appendChild(header);
      section.appendChild(body);
      boxEl.appendChild(section);
    };

    const hasFilter = !!q;
    if (selectedSorted.length) renderSection('selected', '✓ Selected', selectedSorted, true);
    if (enterpriseSorted.length) renderSection('enterprise', '🏢 Enterprise Agents', enterpriseSorted, !selectedSorted.length);
    if (cloudSorted.length) renderSection('cloud', '☁️ Cloud Agents', cloudSorted, hasFilter || false);

    if (eff && boxEl.querySelector('.tep-agent-section')) {
      requestAnimationFrame(() => {
        const sec = boxEl.querySelector(`.tep-agent-section[data-tep-section="${eff}"]`);
        if (!sec) return;
        try {
          sec.scrollIntoView({ block: 'nearest', behavior: 'auto' });
        } catch (_) {
          sec.scrollIntoView(false);
        }
        const body = sec.querySelector('.tep-agent-section-body');
        const next = body && body.querySelector('input[type="checkbox"]:not(:checked)');
        const anyCb = body && body.querySelector('input[type="checkbox"]');
        const toFocus = next || anyCb;
        if (toFocus) {
          try {
            toFocus.focus({ preventScroll: true });
          } catch (_) {
            toFocus.focus();
          }
        }
      });
    }
  }

  function renderAgents(filter) {
    renderAgentPickerSection(agentsBox, filter, selectedAgentIds, {
      emptyText: 'No agents match filter.',
      noAgentsText: 'Agents will load after auth…'
    });
  }

  // ---------------------------------------------------------------------------
  // Manage Tests — state & functions
  // ---------------------------------------------------------------------------
  let allTests = [];
  let selectedTestIds = new Set();
  const testListEl = $('#tep-test-list');
  const testCountEl = $('#tep-test-count');
  const manageTypeFilter = $('#tep-manage-type-filter');
  const manageSearch = $('#tep-manage-search');
  const manageSort = $('#tep-manage-sort');
  const bulkBar = $('#tep-bulk-bar');
  const bulkCount = $('#tep-bulk-count');
  const bulkAction = $('#tep-bulk-action');
  const bulkInterval = $('#tep-bulk-interval');
  const bulkProtocol = $('#tep-bulk-protocol');
  const bulkInsessionLabel = $('#tep-bulk-insession');
  const bulkInsessionCb = $('#tep-bulk-insession-cb');
  const selectBar = $('#tep-select-bar');

  const TYPE_LABELS = {
    'Http': 'HTTP Server', 'A2s': 'Agent→Server', 'Page': 'Page Load',
    'DnsServer': 'DNS Server', 'DnsTrace': 'DNS Trace', 'Bgp': 'BGP',
    'Voip': 'Voice', 'WebTransaction': 'Transaction', 'Ftp': 'FTP',
    'Dnssec': 'DNSSEC', 'OneWayNetwork': 'One-Way'
  };
  const TYPE_CSS = {
    'Http': 'tep-type-http', 'A2s': 'tep-type-a2s', 'Page': 'tep-type-page',
    'DnsServer': 'tep-type-dns', 'DnsTrace': 'tep-type-dns'
  };
  const TYPE_API_PATH = {
    'Http': 'http-server', 'A2s': 'agent-to-server', 'Page': 'page-load',
    'DnsServer': 'dns-server', 'DnsTrace': 'dns-trace',
    'Voip': 'voip', 'WebTransaction': 'web-transaction', 'Ftp': 'ftp',
    'Dnssec': 'dnssec', 'Bgp': 'bgp', 'Network': 'network',
    'HTTP': 'http-server', 'DNS': 'dns-server', 'Voice': 'voip',
    'OneWayNetwork': 'network', 'Sip': 'sip-server'
  };
  const SLUG_REMAP = {
    'browserbot': 'page-load',
    'sip': 'sip-server',
    'webtransaction': 'web-transaction',
    'http server': 'http-server',
    'HTTP Server': 'http-server',
    'agent to server': 'agent-to-server',
    'Agent to Server': 'agent-to-server',
    'page load': 'page-load',
    'Page Load': 'page-load',
    'dns server': 'dns-server',
    'DNS Server': 'dns-server',
    'dns trace': 'dns-trace',
    'DNS Trace': 'dns-trace'
  };
  const NO_API_SLUGS = new Set(['onewaynetwork', 'api']);
  function isReadOnly(t) {
    return NO_API_SLUGS.has((t.type || '').toLowerCase());
  }
  function canEnrich(t) {
    return !isReadOnly(t);
  }

  const TYPE_NORMALIZE = {
    'http-server': 'Http', 'Http': 'Http', 'HTTP': 'Http', 'http_server': 'Http',
    'agent-to-server': 'A2s', 'A2s': 'A2s', 'agent_to_server': 'A2s',
    'Network': 'A2s', 'network': 'A2s',
    'page-load': 'Page', 'Page': 'Page', 'page_load': 'Page',
    'BrowserBot': 'Page', 'browserbot': 'Page',
    'dns-server': 'DnsServer', 'DnsServer': 'DnsServer', 'dns_server': 'DnsServer',
    'dns-trace': 'DnsTrace', 'DnsTrace': 'DnsTrace', 'dns_trace': 'DnsTrace',
    'voice': 'Voip', 'Voip': 'Voip', 'Voice': 'Voip',
    'web-transactions': 'WebTransaction', 'WebTransaction': 'WebTransaction', 'web_transactions': 'WebTransaction',
    'ftp-server': 'Ftp', 'Ftp': 'Ftp', 'ftp_server': 'Ftp',
    'dnssec': 'Dnssec', 'Dnssec': 'Dnssec',
    'bgp': 'Bgp', 'Bgp': 'Bgp'
  };

  function normalizeTest(t) {
    const numMap = {1:'Http', 2:'Page', 3:'A2s', 5:'DnsServer', 6:'DnsTrace', 7:'Voip', 8:'WebTransaction', 12:'Ftp', 14:'Dnssec', 30:'Bgp'};
    if (!t.testType && t.type != null && t.type !== '') {
      if (typeof t.type === 'number') {
        t.testType = numMap[t.type] || ('Type' + t.type);
      } else {
        const key = String(t.type);
        t.testType = TYPE_NORMALIZE[key] || TYPE_NORMALIZE[key.toLowerCase()] || t.type;
      }
    }
    if (t.testType != null && t.testType !== '') {
      if (typeof t.testType === 'number') {
        if (numMap[t.testType]) t.testType = numMap[t.testType];
      } else if (typeof t.testType === 'string') {
        const key = String(t.testType);
        const mapped = TYPE_NORMALIZE[key] || TYPE_NORMALIZE[key.toLowerCase()];
        if (mapped) t.testType = mapped;
      }
    }
    return t;
  }

  function truthyIcmpFlag(v) {
    if (v === 1 || v === true) return true;
    if (v == null) return false;
    const s = String(v).trim().toLowerCase();
    return s === '1' || s === 'true' || s === 'yes';
  }

  /**
   * ICMP network tests: TE list/detail payloads differ — flagIcmp may be nested,
   * protocol may stay "TCP" while port is -1, or only full GET /ajax/tests/network/{aid}/{id} has flags.
   */
  function isNetworkTestIcmp(t) {
    if (!t || typeof t !== 'object') return false;
    const p = String(t.protocol || '').toUpperCase();
    if (p === 'ICMP') return true;
    if (truthyIcmpFlag(t.flagIcmp)) return true;
    const srv = t.server && typeof t.server === 'object' ? t.server : null;
    if (srv) {
      if (String(srv.protocol || '').toUpperCase() === 'ICMP') return true;
      if (truthyIcmpFlag(srv.flagIcmp)) return true;
    }
    const cfg = t.config && typeof t.config === 'object' ? t.config : null;
    if (cfg) {
      if (String(cfg.protocol || '').toUpperCase() === 'ICMP') return true;
      if (truthyIcmpFlag(cfg.flagIcmp)) return true;
    }
    const rawPort = srv && srv.port != null ? srv.port : t.port;
    const pNum = parseInt(rawPort, 10);
    if (pNum !== -1) return false;
    const slug = `${t.testType || ''}|${t.type || ''}`.toLowerCase();
    if (/(^|[^a-z])a2s([^a-z]|$)|network|agent-to-server|agent_to_server/.test(slug)) return true;
    return false;
  }

  function getInterval(t) {
    return t.freqHttp || t.freqA2s || t.freqPage || t.freqDns
      || t.freqVoip || t.freqBgp || t.freqFtp || t.freqSip
      || t.frequency || t.testInterval || t.intervalInSeconds
      || t.interval || 0;
  }

  function formatInterval(seconds) {
    if (!seconds) return '—';
    if (seconds >= 3600) return (seconds / 3600) + 'h';
    if (seconds >= 60) return (seconds / 60) + 'm';
    return seconds + 's';
  }

  function getTestAgentIds(t) {
    if (t.agentSet) {
      if (Array.isArray(t.agentSet.vAgentIds) && t.agentSet.vAgentIds.length) return t.agentSet.vAgentIds;
      if (Array.isArray(t.agentSet.agentIds) && t.agentSet.agentIds.length) return t.agentSet.agentIds;
      if (Array.isArray(t.agentSet.agents) && t.agentSet.agents.length) return t.agentSet.agents.map(a => a.agentId || a.id || a);
    }
    if (Array.isArray(t.agents) && t.agents.length) return t.agents.map(a => a.agentId || a.id || a);
    if (Array.isArray(t.agentIds) && t.agentIds.length) return t.agentIds;
    if (Array.isArray(t.vAgentIds) && t.vAgentIds.length) return t.vAgentIds;
    if (t.config) {
      if (t.config.agentSet && Array.isArray(t.config.agentSet.vAgentIds)) return t.config.agentSet.vAgentIds;
      if (Array.isArray(t.config.agents)) return t.config.agents.map(a => a.agentId || a.id || a);
    }
    return [];
  }

  function testApiUrl(t, { forWrite = false } = {}) {
    let slug = t.type || '';
    const slugLower = slug.toLowerCase();
    if (SLUG_REMAP[slug] || SLUG_REMAP[slugLower]) {
      slug = SLUG_REMAP[slug] || SLUG_REMAP[slugLower];
    } else if (slug && slug === slugLower && /^[a-z0-9-]+$/.test(slug)) {
      // already a valid slug like 'network', 'http-server', 'ftp', 'voip'
    } else {
      slug = TYPE_API_PATH[slug] || TYPE_API_PATH[t.testType] || slugLower;
    }
    if (forWrite) return `/ajax/tests/${slug}`;
    const aid = t.aid;
    const testId = t.testId || t.id;
    return `/ajax/tests/${slug}/${aid}/${testId}`;
  }

  async function fetchTestDetail(t) {
    const url = testApiUrl(t);
    if (!t.aid || !(t.type || t.testType)) { t._agentsLoaded = true; return null; }
    try {
      const resp = await ajax(url);
      if (resp.ok) {
        const detail = await resp.json();
        const preserve = new Set(['testType', '_agentsLoaded', '_fetchStatus', '_fetchError', 'type']);
        for (const k of Object.keys(detail)) {
          if (preserve.has(k)) continue;
          t[k] = detail[k];
        }
        t._agentsLoaded = true;
        return detail;
      }
    } catch (e) { /* silent */ }
    t._agentsLoaded = true;
    return null;
  }

  async function enrichTestsWithAgents() {
    log('Enriching tests with agent data…', 'tep-log-info');
    const BATCH = 5;
    let enriched = 0;
    let debugged = false;

    for (let i = 0; i < allTests.length; i += BATCH) {
      const batch = allTests.slice(i, i + BATCH);
      await Promise.all(batch.map(async (t) => {
        if (t._agentsLoaded) return;
        if (!canEnrich(t)) { t._agentsLoaded = true; return; }
        const detail = await fetchTestDetail(t);

        if (detail && !debugged) {
          debugged = true;
          const agentKeys = Object.keys(detail).filter(k => /agent/i.test(k));
          log(`  Detail keys: ${Object.keys(detail).slice(0,20).join(', ')}`, 'tep-log-info');
          log(`  Agent keys: ${agentKeys.join(', ') || 'none'}`, 'tep-log-info');
          for (const ak of agentKeys) {
            log(`    ${ak}: ${JSON.stringify(detail[ak]).substring(0, 250)}`, 'tep-log-info');
          }
        }
        // Debug: log server-related fields for A2S/network tests
        if (detail && (t.testType === 'A2s' || (t.type || '').toLowerCase() === 'agent-to-server' || (t.type || '').toLowerCase() === 'network')) {
          const srvKeys = Object.keys(detail).filter(k => /server|target|host|port|proto|freq/i.test(k));
          log(`  A2S detail [${t.name}]: ${srvKeys.map(k => k+'='+JSON.stringify(detail[k])).join(', ')}`, 'tep-log-info');
        }

        const count = getTestAgentIds(t).length;
        if (count > 0) enriched++;

        const tid = String(t.testId || t.id || '');
        const card = testListEl.querySelector(`.tep-test-card[data-test-id="${tid}"]`);
        if (card) {
          const metaSpans = card.querySelectorAll('.tep-test-card-meta span');
          if (metaSpans.length >= 4) {
            metaSpans[2].textContent = `${formatInterval(getInterval(t))} interval`;
            metaSpans[3].textContent = `${count} agent(s)`;
          }
        }
      }));
    }

    log(`Agent enrichment complete: ${enriched} of ${allTests.length} test(s) have agents`, 'tep-log-ok');
    renderTests();
  }

  function getTarget(t) {
    if (t.url && typeof t.url === 'object') {
      if (typeof t.url.url === 'string') return t.url.url;
      if (typeof t.url.target === 'string') return t.url.target;
      if (typeof t.url.href === 'string') return t.url.href;
      return String(t.url.url || t.url.target || t.url.href || '');
    }
    if (typeof t.url === 'string' && t.url) return t.url;
    if (t.server && typeof t.server === 'object') return t.server.serverName || '';
    if (t.server) return t.server;
    if (t.domain) return t.domain;
    if (t.target) return t.target;
    if (t.hostname) return t.hostname;
    if (t.testTarget) return t.testTarget;
    if (t.serverName) return t.serverName;
    if (t.destination) return t.destination;
    if (t.config) {
      if (t.config.url && typeof t.config.url === 'object') return t.config.url.url || '';
      if (typeof t.config.url === 'string') return t.config.url;
      if (t.config.server) return t.config.server;
      if (t.config.domain) return t.config.domain;
      if (t.config.target) return t.config.target;
    }
    return '';
  }

  async function loadTests(opts) {
    const o = (opts && typeof opts === 'object') ? opts : {};
    const quiet = !!o.quiet;
    const skipEnrich = !!o.skipEnrich;
    if (!quiet) {
      testListEl.innerHTML = '<span class="tep-log-info">Loading tests…</span>';
    }
    allTests = [];

    const endpoints = [
      '/ajax/settings/tests',
      '/ajax/settings/tests/list',
      '/ajax/network-app-synthetics/test-settings',
      '/ajax/tests/list',
      '/ajax/tests'
    ];

    let found = false;
    for (const ep of endpoints) {
      try {
        const resp = await ajax(ep);
        if (resp.ok) {
          const data = await resp.json();
          if (Array.isArray(data)) {
            allTests = data;
          } else {
            // Try to find arrays of tests inside the response
            for (const k of Object.keys(data)) {
              if (Array.isArray(data[k])) allTests.push(...data[k]);
            }
            // If no arrays found, maybe the response IS the list as object
            if (!allTests.length && typeof data === 'object') {
              // Log structure for debugging
              log(`${ep} → keys: ${Object.keys(data).slice(0, 10).join(', ')}`, 'tep-log-info');
              // Check if values contain test-like objects
              for (const k of Object.keys(data)) {
                const v = data[k];
                if (v && typeof v === 'object' && !Array.isArray(v) && v.testType) {
                  allTests.push(v);
                }
              }
            }
          }
          if (allTests.length) {
            allTests = allTests.map(normalizeTest);
            log(`Loaded ${allTests.length} test(s) from ${ep}`, 'tep-log-ok');
            found = true;
            break;
          } else {
            log(`${ep} → 200 but 0 tests (${typeof data}, keys: ${Object.keys(data).slice(0,5).join(',')})`, 'tep-log-info');
          }
        } else {
          log(`${ep} → ${resp.status}`, 'tep-log-info');
        }
      } catch (e) {
        log(`${ep} → error: ${e.message}`, 'tep-log-info');
      }
    }

    if (!found) {
      log('Could not find test list endpoint. Check log above.', 'tep-log-err');
      if (!quiet) {
        testListEl.innerHTML = '<span class="tep-log-err">Could not load tests — see log.</span>';
      } else {
        toast('Could not load portal tests — see log', 'err');
      }
    } else {
      if (!quiet) {
        renderTests();
        if (!skipEnrich) enrichTestsWithAgents();
      } else {
        log(`Loaded ${allTests.length} portal test(s) (quiet)`, 'tep-log-ok');
      }
    }
  }

  function updateBulkUI() {
    const count = selectedTestIds.size;
    bulkCount.textContent = `${count} selected`;
    bulkBar.classList.toggle('active', count > 0);
  }

  function getFilteredTests() {
    const typeF = manageTypeFilter.value;
    const searchQ = manageSearch.value.toLowerCase();
    let filtered = allTests;
    if (typeF) filtered = filtered.filter(t => t.testType === typeF);
    if (searchQ) filtered = filtered.filter(t =>
      (t.name || '').toLowerCase().includes(searchQ) ||
      getTarget(t).toLowerCase().includes(searchQ)
    );
    const TYPE_ORDER = {
      'http-server': 0, 'Http': 0,
      'network': 1, 'agent-to-server': 1, 'A2s': 1,
      'onewaynetwork': 2, 'agent-to-agent': 2,
      'browserbot': 3, 'page-load': 3, 'Page': 3,
      'web-transaction': 4, 'webtransaction': 4, 'Transaction': 4
    };
    function typeRank(t) {
      const slug = (t.type || '').toLowerCase();
      if (slug in TYPE_ORDER) return TYPE_ORDER[slug];
      const tt = t.testType || '';
      if (tt in TYPE_ORDER) return TYPE_ORDER[tt];
      return 99;
    }
    const sortMode = manageSort.value;
    return filtered.sort((a, b) => {
      if (sortMode === 'modified') {
        const da = a.modifiedDate || a.lastModified || a.dateModified || '';
        const db = b.modifiedDate || b.lastModified || b.dateModified || '';
        if (da || db) return da > db ? -1 : da < db ? 1 : 0;
      }
      if (sortMode === 'created') {
        const da = a.createdDate || a.dateCreated || a.createDate || '';
        const db = b.createdDate || b.dateCreated || b.createDate || '';
        if (da || db) return da > db ? -1 : da < db ? 1 : 0;
      }
      if (sortMode === 'name') {
        return (a.name || '').localeCompare(b.name || '');
      }
      // Default: enabled first, then type, then name
      const ea = a.flagEnabled ? 0 : 1;
      const eb = b.flagEnabled ? 0 : 1;
      if (ea !== eb) return ea - eb;
      const ra = typeRank(a);
      const rb = typeRank(b);
      if (ra !== rb) return ra - rb;
      return (a.name || '').localeCompare(b.name || '');
    });
  }

  function renderTests() {
    const filtered = getFilteredTests();
    testCountEl.textContent = `Showing ${filtered.length} of ${allTests.length} test(s)`;
    selectBar.style.display = allTests.length ? '' : 'none';

    if (!filtered.length) {
      testListEl.innerHTML = '<span class="tep-log-info">No tests match filter.</span>';
      return;
    }

    testListEl.innerHTML = '';
    for (const t of filtered) {
      const tid = String(t.testId || t.id || '');
      const card = document.createElement('div');
      card.className = 'tep-test-card';
      card.dataset.testId = tid;
      const typeCss = TYPE_CSS[t.testType] || 'tep-type-other';
      const typeLabel = TYPE_LABELS[t.testType] || t.testType || '?';
      const target = getTarget(t);
      const interval = getInterval(t);
      const enabled = t.flagEnabled ? 'on' : 'off';
      const agentCount = t._agentsLoaded ? getTestAgentIds(t).length : '…';

      card.innerHTML = `
        <div class="tep-test-card-header">
          <input type="checkbox" class="tep-test-card-check" data-tid="${tid}" ${selectedTestIds.has(tid) ? 'checked' : ''}>
          <span class="tep-type-badge ${typeCss}">${typeLabel}</span>
          <span class="tep-test-card-name" title="${(t.name || '').replace(/"/g, '&quot;')}">${t.name || 'Unnamed'} <a class="tep-test-link" href="/network-app-synthetics/views/?testId=${tid}" target="_blank" title="Open in ThousandEyes">&#x1F517;</a></span>
          <div class="tep-test-actions">
            ${isReadOnly(t) ? '<span style="font-size:10px;color:#64748b;">read-only</span>' : `
            <button data-action="edit" title="Edit">Edit</button>
            <button data-action="clone" title="Clone">Clone</button>
            <button data-action="toggle" title="${t.flagEnabled ? 'Disable' : 'Enable'}">${t.flagEnabled ? 'Disable' : 'Enable'}</button>
            <button data-action="delete" class="tep-btn-danger" title="Delete">Del</button>`}
          </div>
        </div>
        <div class="tep-test-card-meta">
          <span><span class="tep-enabled-dot ${enabled}"></span> ${enabled === 'on' ? 'Enabled' : 'Disabled'}</span>
          <span>${target ? String(target).substring(0, 50) : '—'}</span>
          <span>${formatInterval(interval)} interval</span>
          <span>${agentCount} agent(s)</span>
        </div>
      `;

      // Checkbox handler
      card.querySelector('.tep-test-card-check').addEventListener('change', (e) => {
        if (e.target.checked) selectedTestIds.add(tid); else selectedTestIds.delete(tid);
        updateBulkUI();
      });

      // Action handlers
      card.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const action = btn.dataset.action;

        if (action === 'edit') {
          const dismissLoad = toastProcessing('Loading test…');
          try {
            await fetchTestDetail(t);
          } catch (err) {
            log(`Edit: detail refresh failed — ${err && err.message ? err.message : err}`, 'tep-log-info');
          }
          dismissLoad();
          toggleEditForm(card, t);
        } else if (action === 'clone') {
          await cloneTest(t);
        } else if (action === 'toggle') {
          await toggleTest(t, card);
        } else if (action === 'delete') {
          await deleteTest(t, card);
        }
      });

      testListEl.appendChild(card);
    }
  }

  function toggleEditForm(card, t) {
    const existing = card.querySelector('.tep-edit-form');
    if (existing) { existing.remove(); return; }

    const target = getTarget(t);
    const interval = getInterval(t);
    const testAgentIds = getTestAgentIds(t);
    const currentAgentIds = new Set(testAgentIds.map(String));
    const editAgentIds = new Set(currentAgentIds);

    const form = document.createElement('div');
    form.className = 'tep-edit-form';
    form.innerHTML = `
      <div class="tep-edit-row">
        <label>Name</label>
        <input class="tep-edit-name" value="${(t.name || '').replace(/"/g, '&quot;')}">
      </div>
      <div class="tep-edit-row">
        <label>Target</label>
        <input class="tep-edit-target" value="${target.replace(/"/g, '&quot;')}">
      </div>
      <div class="tep-edit-row">
        <label>Interval</label>
        <select class="tep-edit-interval">
          ${[60,120,300,600,900,1800,3600].map(v =>
            `<option value="${v}" ${v === interval ? 'selected' : ''}>${v/60}m</option>`
          ).join('')}
        </select>
      </div>
      <div class="tep-edit-row">
        <label>Enabled</label>
        <select class="tep-edit-enabled">
          <option value="1" ${t.flagEnabled ? 'selected' : ''}>Enabled</option>
          <option value="0" ${!t.flagEnabled ? 'selected' : ''}>Disabled</option>
        </select>
      </div>
      ${/A2s|Network|Http|Page/i.test(t.testType || t.type || '') ? (() => {
        const isIcmp = isNetworkTestIcmp(t);
        const curProto = isIcmp ? 'ICMP' : (t.probeMode === 'SYN' ? 'TCP-SYN' : 'TCP-SACK');
        const rawPort = (typeof t.server === 'object' && t.server && t.server.port != null) ? t.server.port : t.port;
        const pNum = parseInt(rawPort, 10);
        const portVal = (!isIcmp && Number.isFinite(pNum) && pNum >= 1 && pNum <= 65535) ? pNum : 443;
        return `
      <div class="tep-edit-row" style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;">
        <div>
          <label>Protocol</label>
          <select class="tep-edit-protocol">
            <option value="TCP-SACK" ${curProto === 'TCP-SACK' ? 'selected' : ''}>TCP / SACK</option>
            <option value="TCP-SYN" ${curProto === 'TCP-SYN' ? 'selected' : ''}>TCP / SYN</option>
            <option value="ICMP" ${curProto === 'ICMP' ? 'selected' : ''}>ICMP</option>
          </select>
        </div>
        <div class="tep-edit-tcp-opts" style="${isIcmp ? 'display:none;' : 'display:contents;'}">
          <div>
            <label>Port</label>
            <input type="number" class="tep-edit-port" value="${portVal}" min="1" max="65535" style="width:80px;">
          </div>
          <label style="display:flex;align-items:center;gap:4px;font-size:11px;color:#94a3b8;cursor:pointer;padding-bottom:2px;">
            <input type="checkbox" class="tep-edit-insession" ${t.pathtraceInSession ? 'checked' : ''}> In-Session
          </label>
        </div>
      </div>
      `; })() : ''}
      <div style="margin-top:8px;">
        <label style="font-size:11px;color:#94a3b8;font-weight:600;">Agents (${currentAgentIds.size} assigned)</label>
        <div class="tep-agent-filter-wrap tep-agent-filter-wrap--compact">
          <input class="tep-edit-agent-filter" placeholder="Filter agents…">
          <button type="button" class="tep-agent-filter-clear" title="Clear filter" aria-label="Clear filter">&times;</button>
        </div>
        <div class="tep-edit-agents-box"></div>
      </div>
      <div class="tep-edit-actions">
        <button class="tep-btn tep-btn-primary tep-btn-sm tep-save-edit">Save</button>
        <button class="tep-btn tep-btn-secondary tep-btn-sm tep-cancel-edit">Cancel</button>
      </div>
    `;

    // Render agent checkboxes in the edit form
    const editAgentsBox = form.querySelector('.tep-edit-agents-box');
    const editFilterInput = form.querySelector('.tep-edit-agent-filter');

    function renderEditAgents(filter, focusSection) {
      const q = (filter || '').toLowerCase();
      const filtered = q
        ? agents.filter(a => (a.agentName || '').toLowerCase().includes(q) || (a.agentType || '').toLowerCase().includes(q))
        : agents;
      editAgentsBox.innerHTML = '';
      if (!filtered.length) {
        editAgentsBox.innerHTML = '<span style="font-size:11px;color:#64748b;">No agents match.</span>';
        return;
      }

      const selectedList = filtered.filter((a) => restoreAgentSelectionSetHas(editAgentIds, a.agentId));
      const enterpriseRest = filtered.filter(
        (a) => a.agentType === 'Enterprise' && !restoreAgentSelectionSetHas(editAgentIds, a.agentId)
      );
      const cloudRest = filtered.filter(
        (a) => a.agentType !== 'Enterprise' && !restoreAgentSelectionSetHas(editAgentIds, a.agentId)
      );

      function sortEnt(list) {
        return [...list].sort((a, b) => {
          if (a.status !== b.status) {
            if (a.status === 'online') return -1;
            if (b.status === 'online') return 1;
            if (a.status === 'offline') return 1;
            if (b.status === 'offline') return -1;
          }
          return (a.agentName || '').localeCompare(b.agentName || '');
        });
      }
      function sortSel(list) {
        return [...list].sort((a, b) => {
          const aEnt = a.agentType === 'Enterprise' ? 0 : 1;
          const bEnt = b.agentType === 'Enterprise' ? 0 : 1;
          if (aEnt !== bEnt) return aEnt - bEnt;
          if (a.status !== b.status) {
            if (a.status === 'online') return -1;
            if (b.status === 'online') return 1;
            if (a.status === 'offline') return 1;
            if (b.status === 'offline') return -1;
          }
          return (a.agentName || '').localeCompare(b.agentName || '');
        });
      }
      function sortNm(list) {
        return [...list].sort((a, b) => (a.agentName || '').localeCompare(b.agentName || ''));
      }

      const selectedSorted = sortSel(selectedList);
      const entSorted = sortEnt(enterpriseRest);
      const cloudSorted = sortNm(cloudRest);

      function effectiveEditFocus(cat) {
        if (!cat) return null;
        if (cat === 'selected' && selectedSorted.length) return 'selected';
        if (cat === 'enterprise' && entSorted.length) return 'enterprise';
        if (cat === 'cloud' && cloudSorted.length) return 'cloud';
        if (selectedSorted.length) return 'selected';
        if (entSorted.length) return 'enterprise';
        if (cloudSorted.length) return 'cloud';
        return null;
      }
      const effEdit = effectiveEditFocus(focusSection);

      const renderSection = (sectionKey, title, list, fallbackOpen) => {
        if (!list.length) return;
        const section = document.createElement('div');
        section.className = 'tep-agent-section';
        section.dataset.tepSection = sectionKey;
        section.style.marginBottom = '6px';
        const header = document.createElement('div');
        header.style.cssText = 'font-weight:bold;padding:4px 6px;background:#2a2a2a;border-radius:4px;cursor:pointer;user-select:none;display:flex;justify-content:space-between;align-items:center;font-size:12px;color:#e2e8f0;';
        const shouldOpen = effEdit ? effEdit === sectionKey : fallbackOpen;
        header.innerHTML = `<span>${title} (${list.length})</span><span class="tep-section-arrow">${shouldOpen ? '▼' : '▶'}</span>`;
        const body = document.createElement('div');
        body.className = 'tep-agent-section-body';
        body.style.display = shouldOpen ? '' : 'none';
        header.addEventListener('click', () => {
          const open = body.style.display !== 'none';
          body.style.display = open ? 'none' : '';
          header.querySelector('.tep-section-arrow').textContent = open ? '▶' : '▼';
        });
        for (const agent of list) {
          const aid = String(agent.agentId);
          const lbl = document.createElement('label');
          const checked = restoreAgentSelectionSetHas(editAgentIds, agent.agentId) ? 'checked' : '';
          const statusDot = agent.agentType === 'Enterprise'
            ? `<span class="tep-agent-status ${agent.status}" style="width:6px;height:6px;"></span>` : '';
          const locTxt = agent.location ? ` <span style="color:#64748b;font-size:10px;">${agent.location}</span>` : '';
          lbl.innerHTML = `<input type="checkbox" value="${aid}" ${checked}> ${statusDot} ${agent.agentName || 'Agent ' + aid} <span style="color:#64748b;font-size:10px;">${agent.agentType || ''}</span>${locTxt}`;
          const cb = lbl.querySelector('input');
          cb.addEventListener('change', () => {
            if (cb.checked) editAgentIds.add(aid);
            else editAgentIds.delete(aid);
            renderEditAgents(editFilterInput.value, sectionKey);
          });
          body.appendChild(lbl);
        }
        section.appendChild(header);
        section.appendChild(body);
        editAgentsBox.appendChild(section);
      };

      const hasFilter = !!q;
      if (selectedSorted.length) renderSection('selected', '✓ Selected', selectedSorted, true);
      if (entSorted.length) renderSection('enterprise', '🏢 Enterprise Agents', entSorted, !selectedSorted.length);
      if (cloudSorted.length) renderSection('cloud', '☁️ Cloud Agents', cloudSorted, hasFilter || false);

      if (effEdit && editAgentsBox.querySelector('.tep-agent-section')) {
        requestAnimationFrame(() => {
          const sec = editAgentsBox.querySelector(`.tep-agent-section[data-tep-section="${effEdit}"]`);
          if (!sec) return;
          try {
            sec.scrollIntoView({ block: 'nearest', behavior: 'auto' });
          } catch (_) {
            sec.scrollIntoView(false);
          }
          const body = sec.querySelector('.tep-agent-section-body');
          const next = body && body.querySelector('input[type="checkbox"]:not(:checked)');
          const anyCb = body && body.querySelector('input[type="checkbox"]');
          const toFocus = next || anyCb;
          if (toFocus) {
            try {
              toFocus.focus({ preventScroll: true });
            } catch (_) {
              toFocus.focus();
            }
          }
        });
      }
    }

    renderEditAgents();
    editFilterInput.addEventListener('input', () => renderEditAgents(editFilterInput.value, null));
    const editFilterWrap = editFilterInput && editFilterInput.closest('.tep-agent-filter-wrap');
    if (editFilterWrap && editFilterInput) {
      wireAgentFilterClear(editFilterWrap, editFilterInput, () => renderEditAgents(editFilterInput.value, null));
    }

    // Protocol toggle for edit form
    const editProtoSel = form.querySelector('.tep-edit-protocol');
    const editTcpOpts = form.querySelector('.tep-edit-tcp-opts');
    if (editProtoSel && editTcpOpts) {
      editProtoSel.addEventListener('change', () => {
        editTcpOpts.style.display = editProtoSel.value.startsWith('TCP') ? 'contents' : 'none';
      });
    }

    form.querySelector('.tep-cancel-edit').addEventListener('click', () => form.remove());
    form.querySelector('.tep-save-edit').addEventListener('click', async () => {
      const dismissProcessing = toastProcessing('Saving…');
      const newName = form.querySelector('.tep-edit-name').value.trim();
      const newTarget = form.querySelector('.tep-edit-target').value.trim();
      const newInterval = parseInt(form.querySelector('.tep-edit-interval').value, 10);
      const newEnabled = parseInt(form.querySelector('.tep-edit-enabled').value, 10);

      // Build updated body — start from enriched test, strip internal keys
      const updated = { ...t };
      Object.keys(updated).forEach(k => { if (k.startsWith('_')) delete updated[k]; });
      updated.name = newName;
      updated.flagEnabled = newEnabled;
      updated.flagIgnoreWarnings = 0;

      // Set target
      if (updated.url && typeof updated.url === 'object') updated.url.url = newTarget;
      else if (updated.server !== undefined) {
        // Network/A2S tests use server as { serverName, port }
        if (typeof updated.server === 'object' && updated.server !== null) {
          let host = newTarget.replace(/^https?:\/\//i, '').replace(/[\/\?#].*$/, '').trim();
          let port = updated.server.port || 443;
          const ci = host.lastIndexOf(':');
          if (ci > 0 && !host.includes('[')) {
            const mp = parseInt(host.substring(ci + 1), 10);
            if (mp > 0 && mp < 65536) { port = mp; host = host.substring(0, ci); }
          }
          updated.server = { serverName: host, port: port };
        } else {
          updated.server = newTarget;
        }
      }
      else if (updated.domain !== undefined) updated.domain = newTarget;

      // Set ALL interval/freq fields to new value so the API sees a consistent change
      for (const k of Object.keys(updated)) {
        if (/^(freq|interval)/i.test(k) && typeof updated[k] === 'number') {
          updated[k] = newInterval;
        }
      }
      // Apply protocol settings for A2S/Network/Http/Page tests
      if (editProtoSel) {
        const pv = editProtoSel.value;
        const proto = pv.startsWith('TCP') ? 'TCP' : 'ICMP';
        updated.protocol = proto;
        updated.flagIcmp = proto === 'ICMP' ? 1 : 0;
        if (proto === 'TCP') {
          const is = form.querySelector('.tep-edit-insession');
          updated.probeMode = pv === 'TCP-SYN' ? 'SYN' : 'SACK';
          updated.pathtraceInSession = is ? (is.checked ? 1 : 0) : (updated.pathtraceInSession || 0);
        } else {
          updated.probeMode = 'AUTO';
          updated.pathtraceInSession = 0;
        }
        const portInput = form.querySelector('.tep-edit-port');
        let newPort;
        if (proto === 'ICMP') {
          newPort = -1;
        } else {
          const parsed = portInput ? parseInt(portInput.value, 10) : NaN;
          newPort = Number.isFinite(parsed) && parsed >= 1 && parsed <= 65535 ? parsed : 443;
        }
        if (typeof updated.server === 'object' && updated.server) {
          updated.server.port = newPort;
        } else {
          updated.port = newPort;
        }
      }

      // Ensure freq and interval are always present
      updated.interval = newInterval;
      updated.freq = newInterval;
      if (!updated.dscp && updated.dscp !== 0) {
        const tt = (t.testType || t.type || '').toLowerCase();
        if (/a2s|network|agent/i.test(tt)) updated.dscp = updated.dscp || 0;
      }
      if (!Object.keys(updated).some(k => /^freq/i.test(k))) {
        const tt = (t.testType || t.type || '').toLowerCase();
        if (/page|browser/i.test(tt)) updated.freqPage = newInterval;
        else if (/a2s|agent|network/i.test(tt)) updated.freqA2s = newInterval;
        else if (/dns/i.test(tt)) updated.freqDns = newInterval;
        else updated.freqHttp = newInterval;
      }

      // Set agents
      if (!updated.agentSet) updated.agentSet = { agentSetId: 0, vAgentIds: [], vAgentsFlagEnabled: {} };
      updated.agentSet.vAgentIds = [...editAgentIds].map(id => parseInt(id, 10) || id);

      // Debug: log freq fields being sent
      const freqKeys = Object.keys(updated).filter(k => /freq|interval/i.test(k));
      log(`Saving "${newName}" — freq: ${JSON.stringify(freqKeys.reduce((o,k)=>(o[k]=updated[k],o),{}))} | interval input: ${newInterval}`, 'tep-log-info');

      try {
        const resp = await ajax(testApiUrl(t, { forWrite: true }), {
          method: 'POST',
          body: JSON.stringify(updated)
        });
        dismissProcessing();
        if (resp.ok) {
          log(`  ✓ Updated "${newName}"`, 'tep-log-ok');
          toast(`Test "${newName}" saved successfully.`, 'ok');
          form.remove();
          loadTests();
        } else {
          const txt = await resp.text().catch(() => '');
          log(`  ✗ ${resp.status}: ${txt.substring(0, 200)}`, 'tep-log-err');
          toast(`Failed to save "${newName}": ${resp.status}`, 'err');
        }
      } catch (e) { dismissProcessing(); log(`  ✗ Error: ${e.message}`, 'tep-log-err'); toast(`Error saving "${newName}"`, 'err'); }
    });

    card.appendChild(form);
  }

  async function cloneTest(t) {
    const newName = prompt('Name for cloned test:', (t.name || '') + ' (copy)');
    if (!newName) return;

    const cloned = { ...t };
    delete cloned.testId;
    delete cloned.id;
    delete cloned.createTime;
    delete cloned.modifiedTime;
    cloned.name = newName;

    try {
      log(`Cloning "${t.name}" as "${newName}"…`, 'tep-log-info');
      const resp = await ajax(testApiUrl(t, { forWrite: true }), {
        method: 'POST',
        body: JSON.stringify(cloned)
      });
      if (resp.ok || resp.status === 201) {
        log(`  ✓ Cloned as "${newName}"`, 'tep-log-ok');
        toast(`Test cloned as "${newName}".`, 'ok');
        loadTests();
      } else {
        const txt = await resp.text().catch(() => '');
        log(`  ✗ ${resp.status}: ${txt.substring(0, 200)}`, 'tep-log-err');
      }
    } catch (e) { log(`  ✗ Error: ${e.message}`, 'tep-log-err'); }
  }

  async function toggleTest(t, card) {
    const newState = t.flagEnabled ? 0 : 1;
    const action = newState ? 'Enabling' : 'Disabling';
    try {
      log(`${action} "${t.name}"…`, 'tep-log-info');
      const updated = { ...t, flagEnabled: newState, flagIgnoreWarnings: 0 };
      const resp = await ajax(testApiUrl(t, { forWrite: true }), {
        method: 'POST',
        body: JSON.stringify(updated)
      });
      if (resp.ok) {
        log(`  ✓ ${action.replace('ing', 'ed')} "${t.name}"`, 'tep-log-ok');
        toast(`${action.replace('ing', 'ed')} "${t.name}".`, 'ok');
        loadTests();
      } else {
        const txt = await resp.text().catch(() => '');
        log(`  ✗ ${resp.status}: ${txt.substring(0, 200)}`, 'tep-log-err');
      }
    } catch (e) { log(`  ✗ Error: ${e.message}`, 'tep-log-err'); }
  }

  async function deleteTest(t, card) {
    if (!confirm(`Delete test "${t.name}"? This cannot be undone.`)) return;
    const testId = t.testId || t.id;
    try {
      log(`Deleting "${t.name}"…`, 'tep-log-info');
      const resp = await ajax(testApiUrl(t), {
        method: 'DELETE'
      });
      if (resp.ok) {
        log(`  ✓ Deleted "${t.name}"`, 'tep-log-ok');
        toast(`Deleted "${t.name}".`, 'ok');
        card.remove();
        allTests = allTests.filter(x => (x.testId || x.id) !== testId);
        testCountEl.textContent = `Showing ${testListEl.children.length} of ${allTests.length} test(s)`;
      } else {
        const txt = await resp.text().catch(() => '');
        log(`  ✗ ${resp.status}: ${txt.substring(0, 200)}`, 'tep-log-err');
      }
    } catch (e) { log(`  ✗ Error: ${e.message}`, 'tep-log-err'); }
  }

  async function bulkApply() {
    const action = bulkAction.value;
    if (!action) { log('Select a bulk action first.', 'tep-log-err'); return; }
    const selected = allTests.filter(t => selectedTestIds.has(String(t.testId || t.id)));
    if (!selected.length) { log('No tests selected.', 'tep-log-err'); return; }

    if (action === 'delete') {
      if (!confirm(`Delete ${selected.length} test(s)? This cannot be undone.`)) return;
    }

    log(`Bulk ${action} on ${selected.length} test(s)…`, 'tep-log-info');
    const dismissProcessing = toastProcessing(`Bulk ${action} on ${selected.length} test(s)…`);
    let ok = 0, fail = 0;

    for (const t of selected) {
      if (isReadOnly(t)) { log(`  Skipping "${t.name}" — read-only type`, 'tep-log-info'); fail++; continue; }
      try {
        let resp;
        if (action === 'enable' || action === 'disable') {
          const updated = { ...t, flagEnabled: action === 'enable' ? 1 : 0, flagIgnoreWarnings: 0 };
          resp = await ajax(testApiUrl(t, { forWrite: true }), { method: 'POST', body: JSON.stringify(updated) });
        } else if (action === 'interval') {
          const newInterval = parseInt(bulkInterval.value, 10);
          const updated = { ...t };
          if (updated.freqHttp !== undefined) updated.freqHttp = newInterval;
          else if (updated.freqA2s !== undefined) updated.freqA2s = newInterval;
          else if (updated.freqPage !== undefined) updated.freqPage = newInterval;
          else if (updated.freqDns !== undefined) updated.freqDns = newInterval;
          resp = await ajax(testApiUrl(t, { forWrite: true }), { method: 'POST', body: JSON.stringify(updated) });
        } else if (action === 'protocol') {
          const tt = (t.testType || t.type || '').toLowerCase();
          if (!/a2s|network|http|page/i.test(tt)) { log(`  Skipping "${t.name}" — protocol not applicable`, 'tep-log-info'); fail++; continue; }
          const pv = bulkProtocol.value;
          const proto = pv.startsWith('TCP') ? 'TCP' : 'ICMP';
          const pm = pv === 'TCP-SYN' ? 'SYN' : (pv === 'TCP-SACK' ? 'SACK' : 'AUTO');
          const inSess = proto === 'TCP' ? (bulkInsessionCb.checked ? 1 : 0) : 0;
          const updated = { ...t, flagIgnoreWarnings: 0 };
          updated.protocol = proto;
          updated.flagIcmp = proto === 'ICMP' ? 1 : 0;
          updated.probeMode = proto === 'TCP' ? pm : 'AUTO';
          updated.pathtraceInSession = inSess;
          if (typeof updated.server === 'object' && updated.server) {
            updated.server.port = updated.server.port || 443;
          }
          const writeUrl = testApiUrl(t, { forWrite: true });
          log(`  DEBUG bulk protocol → ${writeUrl} type="${t.type}" testType="${t.testType}"`, 'tep-log-info');
          resp = await ajax(writeUrl, { method: 'POST', body: JSON.stringify(updated) });
        } else if (action === 'delete') {
          resp = await ajax(testApiUrl(t), { method: 'DELETE' });
        }

        if (resp && resp.ok) { ok++; }
        else { fail++; log(`  ✗ "${t.name}" → ${resp ? resp.status : 'no response'}`, 'tep-log-err'); }
      } catch (e) { fail++; log(`  ✗ "${t.name}" error: ${e.message}`, 'tep-log-err'); }
    }

    dismissProcessing();
    log(`Bulk ${action}: ${ok} succeeded, ${fail} failed.`, ok ? 'tep-log-ok' : 'tep-log-err');
    toast(`Bulk ${action}: ${ok} succeeded, ${fail} failed.`, fail ? 'err' : 'ok');
    selectedTestIds.clear();
    updateBulkUI();
    loadTests();
  }

  function textareaLineHeightPx(ta) {
    const st = getComputedStyle(ta);
    const n = parseFloat(st.lineHeight);
    if (Number.isFinite(n) && n > 0) return n;
    const fs = parseFloat(st.fontSize) || 13;
    return Math.round(fs * 1.45);
  }

  /** Per-line + buttons beside targets textarea (non-empty lines only). */
  function syncTargetsCloneGutter() {
    const ta = root.querySelector('#tep-targets');
    const gutter = root.querySelector('#tep-targets-gutter');
    if (!ta || !gutter) return;
    const lh = textareaLineHeightPx(ta);
    const lines = ta.value.split('\n');
    ta.rows = Math.min(28, Math.max(5, lines.length + 2));
    gutter.innerHTML = '';
    lines.forEach((line, i) => {
      const row = document.createElement('div');
      row.className = 'tep-targets-gutter-row';
      row.style.height = lh + 'px';
      if (line.trim()) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'tep-target-clone-line';
        btn.textContent = '+';
        btn.title = 'Clone this line below';
        btn.addEventListener('click', (ev) => {
          ev.preventDefault();
          ev.stopPropagation();
          const parts = ta.value.split('\n');
          const dup = i < parts.length ? parts[i] : '';
          parts.splice(i + 1, 0, dup);
          ta.value = parts.join('\n');
          syncTargetsCloneGutter();
          ta.focus();
          const P = ta.value.split('\n');
          let pos = 0;
          for (let k = 0; k < i + 1 && k < P.length; k++) pos += P[k].length + 1;
          if (pos > ta.value.length) pos = ta.value.length;
          try { ta.setSelectionRange(pos, pos); } catch (_) { /* ignore */ }
        });
        row.appendChild(btn);
      }
      gutter.appendChild(row);
    });
  }

  // ---------------------------------------------------------------------------
  // Tabs (create test type tabs)
  // ---------------------------------------------------------------------------
  tabsContainer.addEventListener('click', (e) => {
    const tab = e.target.closest('.tep-tab');
    if (!tab) return;
    tabsContainer.querySelectorAll('.tep-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    currentType = tab.dataset.type;

    // Show/hide type-specific fields
    $('#tep-a2s-fields').style.display = (currentType === 'http-server' || currentType === 'agent-to-server' || currentType === 'page-load') ? 'flex' : 'none';

    // Update placeholder & name template
    const nameInput = $('#tep-testname');
    const targetsInput = $('#tep-targets');
    switch (currentType) {
      case 'http-server':
        nameInput.value = 'HTTP Test - {target}';
        targetsInput.placeholder = 'https://example.com\nhttps://another.com';
        break;
      case 'agent-to-server':
        nameInput.value = 'A2S Test - {target}';
        targetsInput.placeholder = 'example.com\n10.0.0.1';
        break;
      case 'page-load':
        nameInput.value = 'Page Load - {target}';
        targetsInput.placeholder = 'https://example.com\nhttps://another.com';
        break;
    }
    syncTargetsCloneGutter();
  });

  // A2S protocol toggle — show/hide TCP options when ICMP is selected
  $('#tep-a2s-protocol').addEventListener('change', () => {
    $('#tep-a2s-tcp-opts').style.display = $('#tep-a2s-protocol').value.startsWith('TCP') ? 'contents' : 'none';
  });

  // ---------------------------------------------------------------------------
  // TE internal test body builders (matched to actual TE AJAX format)
  // ---------------------------------------------------------------------------
  function baseBody(name, vAgentIds, aid) {
    return {
      alertSuppressionWindowIds: [],
      alerts: [],
      description: '',
      flagAlertsEnabled: 1,
      flagDeleted: 0,
      flagEnabled: 1,
      flagInstant: 0,
      flagLocked: 0,
      flagShared: 0,
      flagSnapshot: 0,
      labelsIds: null,
      tagIds: [],
      name: name,
      agentInterfaces: {},
      agentSet: { agentSetId: 0, vAgentIds: vAgentIds, vAgentsFlagEnabled: {} },
      flagCloudMonitoring: 0,
      flagRandomizedStartTime: 0,
      flagAvailBw: 0,
      flagContinuousMode: 0,
      flagMtu: 0,
      flagPing: 1,
      numTraceroutes: 3,
      probePacketRate: null,
      flagBgp: 1,
      flagUsePublicBgp: 1,
      privateMonitorSet: { monitorSetId: null, bgpMonitors: [] },
      ipv6Policy: 'USE_AGENT_POLICY',
      pathtraceInSession: 1,
      probeMode: 'AUTO',
      accountBindings: aid ? [String(aid)] : []
    };
  }

  function buildHttpServerBody(name, target, interval, vAgentIds, aid, opts) {
    opts = opts || {};
    const proto = opts.protocol || 'TCP';
    const probeMode = opts.probeMode || 'SACK';
    const inSession = opts.pathtraceInSession != null ? opts.pathtraceInSession : 1;
    const port = opts.port || 443;
    return {
      ...baseBody(name, vAgentIds, aid),
      authType: 'NONE',
      customHeaders: '',
      customHeadersForm: '{}',
      flagAllowUnsafeLegacyRenegotiation: 1,
      defaultResponseCode: true,
      flagCollectProxyNetworkData: 0,
      flagDistributedTracing: false,
      flagIcmp: proto === 'ICMP' ? 1 : 0,
      flagOverrideAgentProxy: 0,
      flagVerifyCertHostname: 1,
      freqHttp: interval,
      httpTimeLimit: 5,
      httpVersion: 2,
      maxRedirects: 10,
      oAuth: { url: { url: '' } },
      overrideResolvedIp: false,
      protocol: proto,
      probeMode: proto === 'TCP' ? probeMode : 'AUTO',
      pathtraceInSession: proto === 'TCP' ? inSession : 0,
      port: port,
      requestMethod: 'GET',
      sslVersion: 0,
      targetResponseTime: 1000,
      url: { url: target },
      userAgent: null,
      testType: 'Http',
      vaultSecrets: [],
      clientCertPresent: false,
      allowVerifyContent: false,
      proxyId: null
    };
  }

  function buildAgentToServerBody(name, target, interval, vAgentIds, aid, opts) {
    opts = opts || {};
    const proto = opts.protocol || 'TCP';
    const probeMode = opts.probeMode || 'SACK';
    const inSession = opts.pathtraceInSession != null ? opts.pathtraceInSession : 1;
    // Strip protocol and path — TE expects a plain hostname or IP
    let host = target.replace(/^https?:\/\//i, '').replace(/[\/\?#].*$/, '').trim();
    let port = opts.port || 443;
    // If host contains :port, extract it (overrides default/opts only if present in target)
    const colonIdx = host.lastIndexOf(':');
    if (colonIdx > 0 && !host.includes('[')) {
      const maybePort = parseInt(host.substring(colonIdx + 1), 10);
      if (maybePort > 0 && maybePort < 65536) { port = maybePort; host = host.substring(0, colonIdx); }
    }
    return {
      ...baseBody(name, vAgentIds, aid),
      freqA2s: interval,
      interval: interval,
      freq: interval,
      server: { serverName: host, port: port },
      protocol: proto,
      dscp: 0,
      testType: 'A2s',
      flagIcmp: proto === 'ICMP' ? 1 : 0,
      flagBgp: 1,
      flagUsePublicBgp: 1,
      ipv6Policy: 'USE_AGENT_POLICY',
      pathtraceInSession: proto === 'TCP' ? inSession : 0,
      probeMode: proto === 'TCP' ? probeMode : 'AUTO'
    };
  }

  function buildPageLoadBody(name, target, interval, vAgentIds, aid, opts) {
    opts = opts || {};
    const proto = opts.protocol || 'TCP';
    const probeMode = opts.probeMode || 'SACK';
    const inSession = opts.pathtraceInSession != null ? opts.pathtraceInSession : 1;
    const port = opts.port || 443;
    return {
      ...baseBody(name, vAgentIds, aid),
      authType: 'NONE',
      customHeaders: '',
      customHeadersForm: '{}',
      flagAllowUnsafeLegacyRenegotiation: 1,
      defaultResponseCode: true,
      flagCollectProxyNetworkData: 0,
      flagIcmp: proto === 'ICMP' ? 1 : 0,
      flagOverrideAgentProxy: 0,
      flagVerifyCertHostname: 1,
      freqHttp: interval,
      freqBrowserbot: Math.max(interval, 120),
      freqHttp: interval,
      httpTimeLimit: 10,
      httpVersion: 2,
      maxRedirects: 10,
      oAuth: { url: { url: '' } },
      overrideResolvedIp: false,
      protocol: proto,
      probeMode: proto === 'TCP' ? probeMode : 'AUTO',
      pathtraceInSession: proto === 'TCP' ? inSession : 0,
      port: port,
      requestMethod: 'GET',
      sslVersion: 0,
      targetResponseTime: 1000,
      url: { url: target },
      userAgent: null,
      testType: 'Page',
      vaultSecrets: [],
      clientCertPresent: false,
      allowVerifyContent: false,
      proxyId: null,
      pageLoadTimeLimit: 10
    };
  }

  const TE_TYPE_MAP = {
    'http-server':     { apiPath: 'http-server',     buildBody: buildHttpServerBody },
    'agent-to-server': { apiPath: 'network',          buildBody: buildAgentToServerBody },
    'page-load':       { apiPath: 'page-load',       buildBody: buildPageLoadBody }
  };

  // ---------------------------------------------------------------------------
  // Create tests via TE internal AJAX API
  // ---------------------------------------------------------------------------
  function resetCreateTestsForm() {
    const ta = root.querySelector('#tep-targets');
    if (ta) ta.value = '';
    syncTargetsCloneGutter();
    selectedAgentIds.clear();
    renderAgents(filterInput.value);
    const nameInput = $('#tep-testname');
    if (nameInput) {
      switch (currentType) {
        case 'http-server':
          nameInput.value = 'HTTP Test - {target}';
          break;
        case 'agent-to-server':
          nameInput.value = 'A2S Test - {target}';
          break;
        case 'page-load':
          nameInput.value = 'Page Load - {target}';
          break;
        default:
          break;
      }
    }
  }

  async function createTests() {
    const nameTemplate = $('#tep-testname').value.trim();
    const targets = $('#tep-targets').value.trim().split('\n').map(s => s.trim()).filter(Boolean);
    const interval = parseInt($('#tep-interval').value, 10);
    const vAgentIds = [...selectedAgentIds];
    const aid = teInitData._currentAid || '';

    if (!targets.length) { log('No targets specified.', 'tep-log-err'); return; }
    if (!vAgentIds.length) { log('No agents selected.', 'tep-log-err'); return; }

    const createBtn = $('#tep-create');
    createBtn.disabled = true;
    const dismissProcessing = toastProcessing(`Creating ${targets.length} test(s)…`);
    const typeInfo = TE_TYPE_MAP[currentType];
    if (!typeInfo) { log(`Unknown test type: ${currentType}`, 'tep-log-err'); createBtn.disabled = false; dismissProcessing(); return; }

    let createOk = 0;
    let createFail = 0;

    for (const target of targets) {
      const testName = nameTemplate.replace(/\{target\}/g, target);

      let body;
      const pv = $('#tep-a2s-protocol').value;
      const protoOpts = {
        protocol: pv.startsWith('TCP') ? 'TCP' : 'ICMP',
        port: parseInt($('#tep-a2s-port').value, 10) || 443,
        probeMode: pv === 'TCP-SYN' ? 'SYN' : (pv === 'TCP-SACK' ? 'SACK' : 'AUTO'),
        pathtraceInSession: $('#tep-a2s-insession').checked ? 1 : 0
      };
      body = typeInfo.buildBody(testName, target, interval, vAgentIds, aid, protoOpts);

      // For network tests, try to fetch an existing one first to discover field format
      if (currentType === 'agent-to-server') {
        const netTest = allTests.find(tt => (tt.type || '').toLowerCase() === 'network');
        if (netTest) {
          try {
            const dUrl = testApiUrl(netTest);
            log(`DEBUG: fetching existing network test: ${dUrl}`, 'tep-log-info');
            const dr = await ajax(dUrl);
            if (dr.ok) {
              const dd = await dr.json();
              const srvKeys = Object.keys(dd).filter(k => /server|target|host|port|proto|freq|url|addr/i.test(k));
              log(`DEBUG A2S fields: ${srvKeys.map(k => k+'='+JSON.stringify(dd[k])).join(', ')}`, 'tep-log-info');
            } else {
              log(`DEBUG: fetch failed ${dr.status}`, 'tep-log-err');
            }
          } catch(e) { log(`DEBUG fetch err: ${e.message}`, 'tep-log-err'); }
        } else {
          log('DEBUG: no existing network test found to inspect', 'tep-log-info');
        }
      }

      log(`Creating ${currentType} test: "${testName}"…`, 'tep-log-info');
      log(`DEBUG POST /ajax/tests/${typeInfo.apiPath} body: ${JSON.stringify({server: body.server, serverName: body.serverName, port: body.port, protocol: body.protocol, testType: body.testType, freqA2s: body.freqA2s, name: body.name})}`, 'tep-log-info');

      try {
        const resp = await ajax(`/ajax/tests/${typeInfo.apiPath}`, {
          method: 'POST',
          body: JSON.stringify(body)
        });

        const respText = await resp.text().catch(() => '');

        if (resp.ok || resp.status === 201) {
          createOk++;
          let data = {};
          try { data = JSON.parse(respText); } catch {}
          const testId = data.testId || data.id || data.test?.testId || '?';
          log(`  ✓ Created "${testName}" (id: ${testId})`, 'tep-log-ok');
          toast(`Created "${testName}" (id: ${testId})`, 'ok');
        } else {
          createFail++;
          log(`  ✗ ${resp.status}: ${respText.substring(0, 300)}`, 'tep-log-err');
          toast(`Failed to create "${testName}": ${resp.status}`, 'err');
        }
      } catch (e) {
        createFail++;
        log(`  ✗ Error: ${e.message}`, 'tep-log-err');
        toast(`Error creating "${testName}"`, 'err');
      }
    }

    createBtn.disabled = false;
    dismissProcessing();
    log('Done.', 'tep-log-info');
    if (createOk === targets.length && targets.length > 0) {
      resetCreateTestsForm();
      log('Create form cleared for the next batch.', 'tep-log-info');
    }
  }

  // ---------------------------------------------------------------------------
  // Event listeners
  // ---------------------------------------------------------------------------

  // Log toggle
  $('#tep-log-toggle').addEventListener('click', () => {
    const btn = $('#tep-log-toggle');
    const logPanel = $('#tep-log');
    btn.classList.toggle('open');
    logPanel.classList.toggle('open');
  });

  $('#tep-log-copy').addEventListener('click', async (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    const text = (logEl.innerText || '').trim();
    if (!text) {
      toast('Log is empty', 'err');
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      toast('Log copied to clipboard', 'ok');
    } catch (_) {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        toast('Log copied to clipboard', 'ok');
      } catch (e2) {
        toast('Copy failed — open Log, select all, copy manually', 'err');
      }
      ta.remove();
    }
  });

  // Top-level view tab switcher (delegated — tabs differ on /dashboard)
  root.querySelector('#tep-view-tabs').addEventListener('click', (e) => {
    const tab = e.target.closest('.tep-view-tab');
    if (!tab || !tab.dataset.view) return;
    root.querySelectorAll('#tep-view-tabs .tep-view-tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');
    root.querySelectorAll('.tep-view-panel').forEach(p => p.classList.remove('active'));
    const panel = root.querySelector(`#tep-panel-${tab.dataset.view}`);
    if (panel) panel.classList.add('active');
    if (tab.dataset.view === 'dashboard' && tab.dataset.dashTab) {
      const dashSub = tab.dataset.dashTab;
      root.querySelectorAll('.tep-dash-tab-panel').forEach((p) => p.classList.remove('active'));
      const subPanel = root.querySelector('#tep-dash-panel-' + dashSub);
      if (subPanel) subPanel.classList.add('active');
    }
    if (tab.dataset.view === 'manage' && allTests.length === 0 && teInitData) {
      loadTests();
    }
  });


  // Create panel listeners
  $('#tep-close').addEventListener('click', () => {
    stopPersistentIntercept();
    root.style.display = 'none';
    resizeHandle.style.display = 'none';
    constrainStyles.update('');
    toggleBtn.textContent = '\u2699\ufe0f';
  });
  $('#tep-load-agents').addEventListener('click', loadAgents);
  $('#tep-create').addEventListener('click', createTests);
  $('#tep-retry-auth').addEventListener('click', () => {
    stopPersistentIntercept();
    log('--- Retrying auth ---', 'tep-log-info');
    initAuth();
  });
  $('#tep-clear-log').addEventListener('click', () => { logEl.innerHTML = ''; });
  filterInput.addEventListener('input', () => renderAgents(filterInput.value));
  const agentFilterWrap = filterInput && filterInput.closest('.tep-agent-filter-wrap');
  if (agentFilterWrap && filterInput) {
    wireAgentFilterClear(agentFilterWrap, filterInput, () => renderAgents(filterInput.value));
  }

  const targetsTa = root.querySelector('#tep-targets');
  if (targetsTa) {
    targetsTa.addEventListener('input', () => syncTargetsCloneGutter());
    if (typeof ResizeObserver !== 'undefined') {
      new ResizeObserver(() => syncTargetsCloneGutter()).observe(targetsTa);
    }
    syncTargetsCloneGutter();
  }

  // Dark mode toggle for TE page
  let darkStyles = null;
  const darkToggle = $('#tep-dark-toggle');
  const TE_DARK_CSS = `
    html { filter: invert(0.9) hue-rotate(180deg); }
    img, svg, video, canvas, [class*="chart"], [class*="map"], [class*="graph"] {
      filter: invert(1) hue-rotate(180deg);
    }
    #te-panel-root, #tep-resize-handle {
      filter: invert(1) hue-rotate(180deg);
    }
  `;
  function toggleDarkMode() {
    if (darkStyles) {
      darkStyles.remove();
      darkStyles = null;
      darkToggle.classList.remove('active');
      localStorage.removeItem('tep-dark-mode');
    } else {
      darkStyles = tepInjectCSS(TE_DARK_CSS);
      darkToggle.classList.add('active');
      localStorage.setItem('tep-dark-mode', '1');
    }
  }
  darkToggle.addEventListener('click', toggleDarkMode);
  // Restore dark mode if it was on
  if (localStorage.getItem('tep-dark-mode') === '1') toggleDarkMode();

  // Manage panel listeners
  $('#tep-manage-load').addEventListener('click', loadTests);
  manageTypeFilter.addEventListener('change', renderTests);
  manageSearch.addEventListener('input', renderTests);
  manageSearch.addEventListener('keydown', (e) => { if (e.key === 'Enter') loadTests(); });
  manageSort.addEventListener('change', renderTests);

  // Bulk controls
  $('#tep-select-all').addEventListener('click', () => {
    allTests.forEach(t => selectedTestIds.add(String(t.testId || t.id)));
    renderTests(); updateBulkUI();
  });
  $('#tep-select-none').addEventListener('click', () => {
    selectedTestIds.clear();
    renderTests(); updateBulkUI();
  });
  $('#tep-select-filtered').addEventListener('click', () => {
    getFilteredTests().forEach(t => selectedTestIds.add(String(t.testId || t.id)));
    renderTests(); updateBulkUI();
  });
  bulkAction.addEventListener('change', () => {
    bulkInterval.style.display = bulkAction.value === 'interval' ? '' : 'none';
    bulkProtocol.style.display = bulkAction.value === 'protocol' ? '' : 'none';
    bulkInsessionLabel.style.display = (bulkAction.value === 'protocol' && bulkProtocol.value.startsWith('TCP')) ? 'flex' : 'none';
  });
  bulkProtocol.addEventListener('change', () => {
    bulkInsessionLabel.style.display = bulkProtocol.value.startsWith('TCP') ? 'flex' : 'none';
  });
  $('#tep-bulk-apply').addEventListener('click', bulkApply);

  if (isDashboardToolsPage()) {
    $('#tep-dash-refresh').addEventListener('click', () => { refreshDashboardEditor(); });
    $('#tep-dash-download').addEventListener('click', downloadDashboardBackup);
    const cleanupRefresh = root.querySelector('#tep-dash-cleanup-refresh');
    if (cleanupRefresh) cleanupRefresh.addEventListener('click', () => { refreshDashboardCleanupList(); });
    const cleanupSort = root.querySelector('#tep-dash-cleanup-sort');
    if (cleanupSort) cleanupSort.addEventListener('click', () => { toggleDashCleanupSortOrder(); });
    const cleanupNone = root.querySelector('#tep-dash-cleanup-select-none');
    if (cleanupNone) {
      cleanupNone.addEventListener('click', () => {
        root.querySelectorAll('.tep-dash-cleanup-cb').forEach((cb) => { cb.checked = false; });
      });
    }
    const cleanupDel = root.querySelector('#tep-dash-cleanup-delete');
    if (cleanupDel) cleanupDel.addEventListener('click', () => { bulkDeleteSelectedDashboards(); });
    updateDashCleanupSortButton();
    syncDashCleanupMeta();
    renderDashCleanupList();
    $('#tep-dash-restore').addEventListener('click', () => { restoreDashboardFromEditor(); });
    const modeEl = root.querySelector('#tep-dash-restore-agent-mode');
    if (modeEl) {
      modeEl.addEventListener('change', syncDashRestoreAgentUi);
      syncDashRestoreAgentUi();
    }
    $('#tep-dash-restore-import-file-btn').addEventListener('click', () => { $('#tep-dash-restore-import-file').click(); });
    $('#tep-dash-restore-import-file').addEventListener('change', (e) => {
      const f = e.target.files && e.target.files[0];
      if (!f) return;
      const r = new FileReader();
      r.onload = () => {
        $('#tep-dash-restore-json').value = r.result;
        $('#tep-dash-restore-meta').textContent = 'Imported restore file: ' + f.name;
        refreshDashboardJsonSummary('restore');
      };
      r.readAsText(f);
      e.target.value = '';
    });
    const backupJsonTa = root.querySelector('#tep-dash-json');
    if (backupJsonTa) {
      backupJsonTa.addEventListener('input', () => { refreshDashboardJsonSummary('backup'); });
    }
    const restoreJsonTa = root.querySelector('#tep-dash-restore-json');
    if (restoreJsonTa) {
      restoreJsonTa.addEventListener('input', () => {
        refreshDashboardJsonSummary('restore');
      });
    }

    const sniffCb = $('#tep-dash-sniff-ajax');
    if (sniffCb) {
      sniffCb.checked = window.__TEP_OPTICS_SNIFF_AJAX__ !== false;
      sniffCb.addEventListener('change', () => {
        window.__TEP_OPTICS_SNIFF_AJAX__ = !!sniffCb.checked;
        dashConsole('info', 'ajax JSON sniff toggled', { on: sniffCb.checked });
        log(`Console JSON sniff (/ajax/ + /namespace/dash-api) ${sniffCb.checked ? 'ON' : 'OFF'}`, 'tep-log-info');
      });
    }
    $('#tep-dash-copy-debug').addEventListener('click', async () => {
      const text = buildDashboardDebugReport();
      try {
        await navigator.clipboard.writeText(text);
        toast('Troubleshooting report copied', 'ok');
        dashConsole('info', 'troubleshooting report copied to clipboard', { chars: text.length });
      } catch (_) {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.cssText = 'position:fixed;left:-9999px;top:0';
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand('copy');
          toast('Diagnostics report copied', 'ok');
        } catch (e2) {
          toast('Copy failed — open Log and copy manually', 'err');
        }
        ta.remove();
      }
    });

    refreshDashboardJsonSummary('backup');
    refreshDashboardJsonSummary('restore');
  }

  // ---------------------------------------------------------------------------
  // Horizontal resize
  // ---------------------------------------------------------------------------
  let resizing = false;
  resizeHandle.addEventListener('mousedown', (e) => {
    resizing = true;
    resizeHandle.classList.add('active');
    e.preventDefault();
  });
  document.addEventListener('mousemove', (e) => {
    if (!resizing) return;
    applyWidth(window.innerWidth - e.clientX);
  });
  document.addEventListener('mouseup', () => {
    if (resizing) { resizing = false; resizeHandle.classList.remove('active'); }
  });

  // ---------------------------------------------------------------------------
  // Init — fully automatic auth detection
  // ---------------------------------------------------------------------------
  initAuth();
})();
