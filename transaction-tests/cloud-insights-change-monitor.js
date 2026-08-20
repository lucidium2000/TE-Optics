/**
 * ThousandEyes Web Transaction test — Cloud Insights operational + event change monitor
 * ---------------------------------------------------------------------------------
 * Runs as a Transaction (Selenium/JS) script. It never drives a browser: every step is
 * an authenticated call to the ThousandEyes v7 API, wrapped in markers so each endpoint
 * gets its own timing series in the test results.
 *
 * What it checks each round:
 *   1. OPERATIONAL — lists the Cloud Insights AWS and Azure integrations and asserts they
 *      are reachable, well-formed, and still match the declared baseline (drift = failure).
 *        GET /v7/cloud-insights/integration/aws    (documented, v7.0.70+)
 *        GET /v7/cloud-insights/integration/azure  (documented, v7.0.70+)
 *   2. EVENTS — pulls the Cloud Insights change/event feed for a rolling window and
 *      classifies entries into configuration changes vs operational changes, failing on
 *      the event types you list.
 *
 * IMPORTANT — endpoint availability:
 *   The Cloud Insights *Integrations* API is public and documented. The Cloud Insights
 *   *events / inventory-change* feed is NOT in the published v7 OpenAPI spec as of
 *   v7.0.96 (2026-07-22) — it is served to the Cloud Insights UI and to the ThousandEyes
 *   MCP server. EVENTS_PATH/EVENTS_BODY below are therefore configurable. Point them at
 *   the request you capture from the Cloud Insights "Events" tab (DevTools → copy as
 *   cURL) for your org. Until then, leave EVENTS_REQUIRED = false and the events stage
 *   degrades to a logged skip on 401/403/404 instead of failing the round.
 *
 * Setup:
 *   - Test type:  Web Transaction
 *   - Target URL: https://api.thousandeyes.com/v7   (unused by the script, but required)
 *   - Credential: store an OAuth bearer token under the name in TOKEN_CREDENTIAL
 *                 (Settings → Credentials). Never inline the token here.
 *   - Interval:   set WINDOW_MINUTES >= the test interval so event windows do not gap.
 */

import fetch from 'node-fetch';
import assert from 'assert';
import { credentials, markers, test } from 'thousandeyes';

/* ------------------------------------------------------------------ config */

const API_BASE = 'https://api.thousandeyes.com/v7';

// Name of the stored credential holding the bearer token.
const TOKEN_CREDENTIAL = 'TE_API_TOKEN';

// Account group to query. Leave '' to use the token's default account group.
const AID = '';

// Rolling look-back for the events stage. Keep >= the test interval.
const WINDOW_MINUTES = 15;

const REQUEST_TIMEOUT_MS = 20000;

/**
 * Baseline of Cloud Insights integrations that must exist and stay unchanged.
 * Leave empty to skip drift checking and only assert the endpoints are healthy.
 * monitoringType values: 'inventory-monitoring' | 'flow-logs-monitoring' (AWS),
 *                        'azure-inventory-monitoring' | 'azure-flow-logs-monitoring'
 */
const EXPECTED_INTEGRATIONS = [
  // { provider: 'aws',   name: 'prod-inventory',  monitoringType: 'inventory-monitoring' },
  // { provider: 'aws',   name: 'prod-flow-logs',  monitoringType: 'flow-logs-monitoring' },
  // { provider: 'azure', name: 'corp-inventory',  monitoringType: 'azure-inventory-monitoring' },
];

// Fail if an account group reports zero integrations at all.
const REQUIRE_AT_LEAST_ONE_INTEGRATION = true;

/* -- events feed (see the availability note in the header) ----------------- */

const EVENTS_REQUIRED = false;              // true => 401/403/404 fails the round
const EVENTS_METHOD = 'POST';
const EVENTS_PATH = '/cloud-insights/events-analysis/inputs';

// Extra filters merged into the events request body. Empty = whole account group.
const EVENTS_FILTERS = {
  // serviceProvider: 'AWS',
  // entityFilters: { 'CEA-REGION': ['us-east-1'] },
};

// Event type / name substrings that should fail the round outright (case-insensitive).
const FAIL_ON_EVENT_TYPES = [
  // 'INSTANCE_TERMINATED',
  // 'SECURITY_GROUP',
];

// Fail if the window contains more than this many events. 0 = no cap.
const MAX_EVENTS_IN_WINDOW = 0;

// Substrings used to split events into "configuration" vs "operational" changes.
const CONFIG_EVENT_HINTS = ['config', 'route', 'security', 'acl', 'policy', 'rule',
                            'tag', 'attach', 'detach', 'peering', 'subnet', 'vpc', 'vnet'];
const OPERATIONAL_EVENT_HINTS = ['state', 'status', 'scal', 'launch', 'terminat', 'stop',
                                 'start', 'reboot', 'health', 'available', 'unavailable'];

/* ----------------------------------------------------------------- helpers */

function authHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/hal+json, application/json',
    'Content-Type': 'application/json',
    'User-Agent': 'thousandeyes-transaction/cloud-insights-change-monitor',
  };
}

function withAid(path) {
  if (!AID) return path;
  return path + (path.includes('?') ? '&' : '?') + `aid=${encodeURIComponent(AID)}`;
}

/**
 * Fetch + timing marker + status/JSON handling.
 * Returns { status, body } — body is the parsed JSON, or null when the response
 * was not JSON. Never throws on a non-2xx; the caller decides what is fatal.
 */
async function apiCall(marker, path, { method = 'GET', body = null, token } = {}) {
  const url = API_BASE + withAid(path);
  const options = {
    method,
    headers: authHeaders(token),
    timeout: REQUEST_TIMEOUT_MS,
  };
  if (body !== null) options.body = JSON.stringify(body);

  markers.start(marker);
  let response;
  try {
    response = await fetch(url, options);
  } catch (err) {
    markers.stop(marker);
    throw new Error(`${method} ${path} failed at the transport layer: ${err.message}`);
  }
  const text = await response.text();
  markers.stop(marker);

  let parsed = null;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    parsed = null;
  }

  console.log(`${method} ${path} -> ${response.status} (${text.length} bytes)`);
  return { status: response.status, body: parsed, raw: text };
}

function signature(entry) {
  return `${entry.provider}|${entry.name}|${entry.monitoringType}`;
}

/* ------------------------------------------------ stage 1: operational state */

/**
 * Lists one provider's Cloud Insights integrations and validates the payload shape.
 * A malformed or non-200 response is fatal — that is the operational signal.
 */
async function checkProvider(provider, token) {
  const requiredFields = provider === 'aws'
    ? ['id', 'name', 'monitoringType', 'roleArn']
    : ['id', 'name', 'monitoringType', 'azureTenantId'];

  const { status, body, raw } = await apiCall(
    `ci-integrations-${provider}`,
    `/cloud-insights/integration/${provider}`,
    { token }
  );

  assert.strictEqual(
    status, 200,
    `Cloud Insights ${provider.toUpperCase()} integrations returned HTTP ${status}: ${raw.slice(0, 300)}`
  );
  assert.ok(body, `Cloud Insights ${provider.toUpperCase()} integrations returned non-JSON body`);
  assert.ok(
    Array.isArray(body.integrations),
    `Cloud Insights ${provider.toUpperCase()} response is missing the "integrations" array`
  );

  const entries = body.integrations.map((item) => {
    for (const field of requiredFields) {
      assert.ok(
        item[field] !== undefined && item[field] !== null && item[field] !== '',
        `${provider.toUpperCase()} integration "${item.name || item.id || '<unnamed>'}" ` +
        `is missing required field "${field}" — the integration is not fully configured`
      );
    }
    return {
      provider,
      id: item.id,
      name: item.name,
      monitoringType: item.monitoringType,
    };
  });

  console.log(`  ${provider}: ${entries.length} integration(s) — ` +
              (entries.map((e) => `${e.name}[${e.monitoringType}]`).join(', ') || 'none'));
  return entries;
}

/** Compares the live integration set against EXPECTED_INTEGRATIONS. */
function assertNoIntegrationDrift(live) {
  if (EXPECTED_INTEGRATIONS.length === 0) {
    console.log('Baseline drift check skipped (EXPECTED_INTEGRATIONS is empty).');
    return;
  }

  const liveSigs = new Set(live.map(signature));
  const expectedSigs = new Set(EXPECTED_INTEGRATIONS.map(signature));

  const missing = [...expectedSigs].filter((s) => !liveSigs.has(s));
  const added = [...liveSigs].filter((s) => !expectedSigs.has(s));

  if (missing.length || added.length) {
    const parts = [];
    if (missing.length) parts.push(`missing: ${missing.join(', ')}`);
    if (added.length) parts.push(`unexpected: ${added.join(', ')}`);
    throw new Error(`Cloud Insights integration drift detected — ${parts.join(' | ')}`);
  }
  console.log(`Baseline matched (${expectedSigs.size} integration(s)).`);
}

/* --------------------------------------------------- stage 2: change events */

/**
 * Walks an arbitrary events payload and pulls out anything that looks like an event
 * record. The feed is not in the public spec, so this reads defensively rather than
 * binding to one schema: it collects objects from any of the known container keys.
 */
function extractEvents(payload) {
  const found = [];
  const seen = new Set();

  const visit = (node, depth) => {
    if (!node || depth > 6) return;
    if (Array.isArray(node)) {
      node.forEach((child) => visit(child, depth + 1));
      return;
    }
    if (typeof node !== 'object') return;

    const label = node.eventType || node.type || node.name || node.field || node.changeType;
    const stamp = node.timestamp || node.date || node.startDate || node.changedAt || node.time;
    if (label && stamp) {
      const key = `${label}|${stamp}|${node.entityId || node.id || ''}`;
      if (!seen.has(key)) {
        seen.add(key);
        found.push({ label: String(label), timestamp: String(stamp), entity: node.entityId || node.id || null });
      }
    }

    for (const key of ['events', 'items', 'results', 'changeTimeline', 'recurrenceGroups',
                       'entities', 'changes', 'data', 'timeline']) {
      if (node[key]) visit(node[key], depth + 1);
    }
  };

  visit(payload, 0);
  return found;
}

function classify(label) {
  const lower = label.toLowerCase();
  if (CONFIG_EVENT_HINTS.some((hint) => lower.includes(hint))) return 'configuration';
  if (OPERATIONAL_EVENT_HINTS.some((hint) => lower.includes(hint))) return 'operational';
  return 'other';
}

async function checkEvents(token, startDate, endDate) {
  const body = EVENTS_METHOD === 'GET' ? null : Object.assign({
    startDate: startDate.toISOString(),
    endDate: endDate.toISOString(),
  }, EVENTS_FILTERS);

  const path = EVENTS_METHOD === 'GET'
    ? `${EVENTS_PATH}?startDate=${encodeURIComponent(startDate.toISOString())}` +
      `&endDate=${encodeURIComponent(endDate.toISOString())}`
    : EVENTS_PATH;

  const { status, body: payload, raw } = await apiCall('ci-events', path, {
    method: EVENTS_METHOD,
    body,
    token,
  });

  if ([401, 403, 404, 405, 501].includes(status)) {
    const message = `Cloud Insights events feed unavailable at ${EVENTS_METHOD} ${EVENTS_PATH} ` +
                    `(HTTP ${status}). Point EVENTS_PATH at the request your Cloud Insights ` +
                    `UI issues, or leave this stage disabled.`;
    if (EVENTS_REQUIRED) throw new Error(message);
    console.log(`SKIPPED: ${message}`);
    return null;
  }

  assert.strictEqual(
    status, 200,
    `Cloud Insights events feed returned HTTP ${status}: ${raw.slice(0, 300)}`
  );
  assert.ok(payload, 'Cloud Insights events feed returned non-JSON body');

  const events = extractEvents(payload);
  const buckets = { configuration: 0, operational: 0, other: 0 };
  events.forEach((event) => { buckets[classify(event.label)] += 1; });

  console.log(`Events in the last ${WINDOW_MINUTES}m: ${events.length} ` +
              `(configuration ${buckets.configuration}, operational ${buckets.operational}, ` +
              `other ${buckets.other})`);
  events.slice(0, 25).forEach((event) => {
    console.log(`  [${classify(event.label)}] ${event.timestamp} ${event.label}` +
                (event.entity ? ` (${event.entity})` : ''));
  });

  const blocked = events.filter((event) =>
    FAIL_ON_EVENT_TYPES.some((needle) => event.label.toLowerCase().includes(needle.toLowerCase()))
  );
  if (blocked.length) {
    throw new Error(
      `Cloud Insights reported ${blocked.length} blocking change event(s) in the last ` +
      `${WINDOW_MINUTES}m: ${blocked.map((e) => `${e.label}@${e.timestamp}`).join(', ')}`
    );
  }

  if (MAX_EVENTS_IN_WINDOW > 0 && events.length > MAX_EVENTS_IN_WINDOW) {
    throw new Error(
      `Cloud Insights change rate exceeded: ${events.length} events in the last ` +
      `${WINDOW_MINUTES}m (limit ${MAX_EVENTS_IN_WINDOW})`
    );
  }

  return buckets;
}

/* -------------------------------------------------------------------- main */

runScript();

async function runScript() {
  const token = credentials.get(TOKEN_CREDENTIAL);
  assert.ok(token, `No stored credential named "${TOKEN_CREDENTIAL}" — add it under Settings → Credentials`);

  const settings = test.getSettings();
  const endDate = new Date();
  const startDate = new Date(endDate.getTime() - WINDOW_MINUTES * 60 * 1000);
  console.log(`Cloud Insights check — account group ${AID || '<token default>'}, ` +
              `window ${startDate.toISOString()} .. ${endDate.toISOString()}, ` +
              `test timeout ${settings.timeout}s`);

  // Stage 1 — operational state of the Cloud Insights integrations.
  markers.start('cloud-insights-operational');
  const aws = await checkProvider('aws', token);
  const azure = await checkProvider('azure', token);
  const live = aws.concat(azure);

  if (REQUIRE_AT_LEAST_ONE_INTEGRATION) {
    assert.ok(
      live.length > 0,
      'Cloud Insights reports zero AWS and zero Azure integrations — inventory and flow ' +
      'log collection cannot be running for this account group'
    );
  }
  assertNoIntegrationDrift(live);
  markers.stop('cloud-insights-operational');

  // Stage 2 — configuration and operational change events in the rolling window.
  markers.start('cloud-insights-events');
  await checkEvents(token, startDate, endDate);
  markers.stop('cloud-insights-events');

  console.log('Cloud Insights check passed.');
}
