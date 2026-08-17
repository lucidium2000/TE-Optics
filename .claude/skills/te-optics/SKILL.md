---
name: te-optics
description: >-
  Working playbook for the TE-Optics project — a ThousandEyes browser panel
  delivered as a bookmarklet (repo at /Users/chunt2/TE-Optics, source in
  src/panel.js). Use this whenever the task touches TE-Optics in any way:
  editing src/panel.js, the panel.js loader, panel.min.js, index.html or
  mirror.html; anything about "the panel", "the bookmarklet", the ThousandEyes
  dashboard map / trace overlay / device topology / SNMP devices / endpoint
  agents view; bumping TEP_VERSION; building, committing, shipping, or flushing
  the CDN; or any perf/geocoding/UX work on the map. It captures the
  three-file build architecture, the exact ship-and-flush procedure (with the
  jsDelivr staleness gotcha), the conventions that will bite you, the security
  rule for user-supplied curl captures, and a map of the codebase. Reach for it
  even when the user doesn't say "TE-Optics" explicitly but is clearly in this
  repo or talking about this panel — the build/ship rules are easy to get wrong
  from first principles.
---

# TE-Optics

TE-Optics is a **single-file browser panel that augments the ThousandEyes web
app** (`app.thousandeyes.com` / `app.thousandeyes.us`). It runs only on those
origins; the source no-ops / redirects elsewhere. It's installed as a
**bookmarklet** that injects a `<script src>` from jsDelivr — not a giant inlined
`javascript:` URL — so there's no URL-length limit and TE's CSP already allows
the jsDelivr origin. It's a read-only overlay: a world map of Enterprise +
Endpoint + Cloud agents, SaaS/Network health, a live trace overlay, a Device
Layer (SNMP) topology view, alerts, and more.

The user (repo owner: `lucidium2000` on GitHub) ships small, frequent, versioned
changes and tests them live in the real TE dashboard via the bookmarklet — so a
change isn't "done" until it's built, pushed, **and the CDN is flushed**.

## The one rule that matters most: three files, one purpose

```
src/panel.js   ← THE SOURCE OF TRUTH. Edit ONLY this. ~30k lines, all logic + CSS.
panel.min.js   ← generated build (esbuild, whitespace-only strip). Never hand-edit.
panel.js       ← tiny loader shim (~2 KB). Injects panel.min.js. Never put logic here.
```

- **`src/panel.js`** is the commented source. Every code/CSS/behavior change goes here.
- **`panel.min.js`** is produced by `npm run build` (`scripts/build-min.js` → esbuild
  `minifyWhitespace:true`, `minifyIdentifiers:false`, `minifySyntax:false`,
  `legalComments:'none'`, license banner preserved verbatim). It's semantically
  identical to the source, just smaller (~-33%). **Regenerate it after every
  source change; never edit it by hand.**
- **`panel.js`** exists ONLY because everyone's installed bookmark already points
  at the `…/panel.js` URL. It's a fixed loader that injects
  `panel.min.js?<Date.now()>`. Leave it alone unless the loader itself changes.

The installer bookmarklets in `index.html` / `mirror.html` also point at
`…/panel.js`, so old and new installs share one canonical URL and always pull the
minified build. This is also documented in
`.cursor/rules/installer-bookmarklet.mdc`.

## Ship procedure (every change that goes live)

Do all of these, in order. Skipping the flush is the most common mistake — the
change will be on GitHub but users keep getting the old code.

1. Edit `src/panel.js`.
2. **Bump `TEP_VERSION`** (a `const` near the top of `src/panel.js`, e.g.
   `const TEP_VERSION = '3.90';`) and update the displayed version in
   `index.html`: `<span class="install-version" aria-label="Build">3.90</span>`.
   (`mirror.html` shows the build number live — no manual edit there.)
3. `npm run build` (regenerates `panel.min.js`).
4. Syntax-check all three: `node -c src/panel.js && node -c panel.min.js && node -c panel.js`.
   (The min file is one giant line, so `node -c` is your real correctness gate —
   there's no linter step.)
5. Commit `src/panel.js`, `panel.min.js`, `index.html` (and `mirror.html` if touched).
   End commit messages with the Co-Authored-By trailer the repo uses.
6. `git push origin main` (jsDelivr serves `@refs/heads/main`).
7. **Flush the CDN — BOTH files:**
   ```bash
   curl -s "https://purge.jsdelivr.net/gh/lucidium2000/TE-Optics@refs/heads/main/panel.min.js" -o /dev/null -w "%{http_code}\n"
   curl -s "https://purge.jsdelivr.net/gh/lucidium2000/TE-Optics@refs/heads/main/panel.js" -o /dev/null -w "%{http_code}\n"
   ```
8. **Verify the rollover** by fetching and confirming the new version is served:
   ```bash
   curl -s "https://cdn.jsdelivr.net/gh/lucidium2000/TE-Optics@refs/heads/main/panel.min.js" | grep -o 'TEP_VERSION="3.90"' | head -1
   ```
   Seeing `TEP_VERSION="3.90"` in the served file is the definitive proof. (Note:
   esbuild converts the source's single quotes to double quotes, so grep for
   `TEP_VERSION="X.YZ"`.)

### The jsDelivr staleness gotcha (important)

`@refs/heads/main` is Cloudflare-cached with a long `s-maxage` (~12h). The
bookmark's `?<Date.now()>` query busts the **browser** cache, NOT jsDelivr — so
after a push, the CDN keeps serving the old build until you purge. And a plain
read-only poll of the stale URL just **re-warms** the stale entry. The reliable
pattern is **purge, then immediately fetch and check the version** (step 8). If
the fetched content shows the new `TEP_VERSION`, it rolled over. `@main` and
pinned-SHA URLs update sooner, but the bookmark uses `@refs/heads/main`, so
that's the one to verify.

## Conventions that will bite you if you don't know them

- **CSS lives inside a JS template literal (backticks).** The entire stylesheet
  is a big backtick string in `src/panel.js`. **Never put a backtick in a CSS
  comment or value** — it closes the template literal and breaks the build
  (`node -c` will catch it, but you'll waste a cycle). Write comments in plain
  ASCII; avoid stray non-English characters too.
- **Class prefix is `tep-`**, with BEM-ish modifiers (`--dense`, `--zoomed`,
  `--full`, `--glow`, `--loss`). New classes follow the same pattern.
- **Decision provenance in comments.** When a value/behavior comes from the user,
  the codebase notes it inline (e.g. `// CONFIRMED via user request`). Keep this
  up — it's how the "why" survives. Explain reasoning in comments generously;
  the file is long-lived and the rationale matters more than the line.
- **Tunable thresholds are named consts**, grouped and commented (e.g.
  `TEP_TRACE_LITE_N`, `TEP_MAP_DENSE_N`, `TEP_TRACE_HOVER_DELAY_MS`,
  `CLUSTER_MI`, `MAX_ENDPOINT_AGENTS`). When you add a magic number that a user
  might want to tune, make it a named const with a one-line rationale.
- **No test suite / linter.** `node -c` on all three files is the check. For UI
  correctness the user tests live in the real dashboard after you ship, or you
  build a throwaway harness (extract funcs + CSS, inject captured JSON, serve on
  localhost, screenshot) for rendering-heavy work.
- **Line numbers drift constantly** (it's one 30k-line file under active edit).
  Anchor by function/const name and `grep`, not by remembered line numbers.

## Security: user-supplied curl captures

The user frequently pastes `curl` captures from the live TE app to show request
shapes. **These contain live auth material** — `Cookie`, `JSESSIONID`, `_abck`,
`_csrf`, `route`, bearer tokens, etc. When working from a capture, reference
**only** URL paths, request/response body **structure**, and header **names**.
**Never reproduce, echo, quote, commit, or store the auth values** (not in code,
comments, memory files, or your replies). This rule is non-negotiable and is
recorded in the project memory files.

## Deeper knowledge

`src/panel.js` is large and organized into loosely-coupled subsystems. For a map
of those subsystems (the dashboard agent map, the fullscreen trace overlay,
geocoding, the Device Layer / SNMP topology view, endpoint-agent loading,
clustering, markers), the key functions/globals in each, the ThousandEyes domain
concepts they rely on, and the established performance patterns, read:

- **`references/codebase-map.md`** — subsystem-by-subsystem tour + domain glossary
  + the perf playbook (lite-modes, what's expensive, what to avoid).

Read it whenever a task goes beyond the build/ship mechanics into actually
changing behavior — especially anything touching the map, traces, geocoding, or
performance.

## Project memory

The user keeps auto-memory at
`/Users/chunt2/.claude/projects/-Users-chunt2-TE-Optics/memory/` (indexed by
`MEMORY.md`). Relevant files include the SNMP Device Layer API notes and the
endpoint-agent map perf notes. Check there for prior decisions before
re-deriving, and keep the security rule above in mind — memory must not contain
captured auth values either.
