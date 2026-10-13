---
name: te-optics
description: >-
  Working playbook for the TE-Optics project — a ThousandEyes browser panel
  delivered as a bookmarklet (repo at /Users/chunt2/TE-Optics, source in
  src/panel.js). Use this whenever the task touches TE-Optics in any way:
  editing src/panel.js, the panel.js loader, panel.build.js/panel.min.js, index.html or
  mirror.html; anything about "the panel", "the bookmarklet", the ThousandEyes
  dashboard map / trace overlay / device topology / SNMP devices / endpoint
  agents view; bumping TEP_VERSION; building, committing, shipping, or flushing
  the CDN; or any perf/geocoding/UX work on the map. It captures the
  four-file build architecture, the exact ship-and-flush procedure (with the
  jsDelivr auto-minify trap that has taken the panel down), the conventions
  that will bite you, the security
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

## The one rule that matters most: four files, one purpose

```
src/panel.js    ← THE SOURCE OF TRUTH. Edit ONLY this. ~37k lines, all logic + CSS.
panel.build.js  ← generated build, THE ONE THE LOADER FETCHES. Never hand-edit.
panel.min.js    ← the SAME bytes under the old name, kept as the loader's fallback.
panel.js        ← the loader shim (~40 KB). Injects the build. Never put logic here.
```

**`npm run build` writes `panel.build.js` and `panel.min.js` with identical
bytes.** Commit both. The duplication is not cosmetic — see the trap below.

- **`src/panel.js`** is the commented source. Every code/CSS/behavior change goes here.
- **`panel.build.js` / `panel.min.js`** are produced by `npm run build` (`scripts/build-min.js` → esbuild
  `minifyWhitespace:true`, `minifyIdentifiers:false`, `minifySyntax:false`,
  `legalComments:'none'`, license banner preserved verbatim). It's semantically
  identical to the source, just smaller (~-33%). **Regenerate it after every
  source change; never edit it by hand.**
- **`panel.js`** exists ONLY because everyone's installed bookmark already points
  at the `…/panel.js` URL. It injects the build with a `?<Date.now()>` cache
  buster, trying `@main/panel.build.js` first and falling back to
  `@main/panel.min.js`. Leave it alone unless the loader itself changes.
  **The bookmarklet URL can never change** — too many people have it installed —
  but the loader's CONTENTS are freely updatable, and that is the lever for any
  delivery change. Changing how the panel is fetched never requires anyone to
  reinstall anything.

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
3. `npm run build` (regenerates `panel.build.js` AND `panel.min.js`).
4. Syntax-check all four: `node -c src/panel.js && node -c panel.build.js && node -c panel.min.js && node -c panel.js`.
   (The build is one giant line, so `node -c` is your real correctness gate —
   there's no linter step.)
5. Commit `src/panel.js`, `panel.build.js`, `panel.min.js`, `index.html` (and
   `mirror.html` if touched). End commit messages with the Co-Authored-By
   trailer the repo uses.
6. `git push origin main` (the build is served from `@main`).
7. **Flush the CDN — the build. Purge BOTH names:**
   ```bash
   curl -s "https://purge.jsdelivr.net/gh/lucidium2000/TE-Optics@main/panel.build.js" -o /dev/null -w "%{http_code}\n"
   curl -s "https://purge.jsdelivr.net/gh/lucidium2000/TE-Optics@main/panel.min.js"   -o /dev/null -w "%{http_code}\n"
   ```
8. **Verify the rollover** on the name the loader actually fetches:
   ```bash
   curl -s "https://cdn.jsdelivr.net/gh/lucidium2000/TE-Optics@main/panel.build.js" | grep -o 'TEP_VERSION="3.90"' | head -1
   ```
   Check the SIZE too, not just the version string — a few hundred KB where you
   expected ~1.4 MB means jsDelivr served something it generated rather than
   your build (see the trap below).
   ```bash
   curl -s -o /tmp/b "https://cdn.jsdelivr.net/gh/lucidium2000/TE-Optics@main/panel.build.js"; wc -c < /tmp/b   # vs: wc -c < panel.build.js
   ```
   Seeing `TEP_VERSION="3.90"` in the served file is the proof. (esbuild converts
   the source's single quotes to double quotes, so grep for `TEP_VERSION="X.YZ"`.)
   **Caveat:** jsDelivr refreshes a branch's HEAD→commit pointer on its own
   schedule, and a file purge does NOT force it — so `@main` can serve the
   previous commit's build for a while after a push. This is a *version-lag*, not
   a broken deploy; the panel still loads. If a release must go live instantly,
   pin/verify via the pushed SHA (`@<sha>/panel.build.js`, immutable) and know
   that `@main` will catch up. That same stale-metadata machinery is what caused
   the 13 Oct 2026 outage — a *version*-lag is harmless, but when it convinces
   jsDelivr a file is missing it stops being harmless. See the trap below.
9. **Only if you changed the LOADER** (`panel.js`) or the bookmarklet: also mirror
   the loader onto the `refs` branch and purge it — see the delivery model below.

### Delivery model — READ THIS (it is not the obvious one)

The distributed bookmark URL is **`…/gh/lucidium2000/TE-Optics@refs/heads/main/panel.js`**
and CANNOT change (it's in everyone's installed bookmark). But jsDelivr changed
how it parses that URL: it now reads **`@refs`** as the ref and **`heads/main/panel.js`**
as the path (it used to treat `refs/heads/main` as a full branch ref). So the URL
only resolves because a git branch **literally named `refs`** exists with the
loader at path **`heads/main/panel.js`**. That branch is the whole reason the old
bookmarks still work — do not delete it.

The chain, end to end:
- `@refs/heads/main/panel.js` → ref `refs`, file `heads/main/panel.js` → the loader.
- The loader injects **`@main/panel.build.js`** → main-branch root `panel.build.js`
  → the build. `@main/panel.min.js` is its fallback only.

Consequences:
- **The build lives on `main`** under both names and is delivered via `@main`
  (real files, so jsDelivr serves them directly). The ship steps above cover both.
- **THE AUTO-MINIFY TRAP — the single worst failure this project has had.**
  When jsDelivr is asked for an `X.min.js` it believes is absent, it does not
  404. It runs Terser over `X.js` and serves THAT, with a banner saying so:

  ```
  /**
   * Minified by jsDelivr using Terser v5.48.0.
   * Original file: /gh/lucidium2000/TE-Optics@main/panel.js
   */
  ```

  Since `panel.js` is the LOADER, the result is a bookmarklet that injects a
  minified copy of itself. Nothing boots, and a purge does not fix it.

  It bit twice:
  - `@refs/heads/main/panel.min.js` parses to `heads/main/panel.min.js` on the
    `refs` branch, which does not exist → a wrong ~500-byte stub. **Never point
    anything there.**
  - **13 Oct 2026 — a live outage on `@main/panel.min.js` itself.** jsDelivr's
    *metadata* for the branch went a month stale (its listing reported
    `panel.js` at 1872 bytes and `panel.min.js` at 1321235 — the sizes from
    commit `6824a3b`, v4.06, 11 Sep) and it synthesised the file. The file was
    never missing: `git ls-tree origin/main` had it, and `@<sha>/panel.min.js`
    served it perfectly throughout.

  **This is why the loader asks for `panel.build.js` first.** A name that is not
  `<something>.min.js` cannot be synthesised from anything — jsDelivr either
  serves the real file or 404s, and a 404 falls through to the next source.
  Never make the primary delivery name end in `.min.js` again.

  **Diagnosing it:** content and metadata are different layers and fail
  independently. `@main/index.html` and `@main/src/panel.js` kept serving the
  CURRENT files while `panel.min.js` was poisoned, so "other files look fine"
  proves nothing. Compare jsDelivr's own listing against git:

  ```bash
  curl -s "https://data.jsdelivr.com/v1/packages/gh/lucidium2000/TE-Optics@main?structure=flat" \
    | python3 -c "import json,sys; [print(f['name'], f['size']) for f in json.load(sys.stdin)['files'] if 'panel' in f['name']]"
  git ls-tree -l origin/main panel.js panel.build.js panel.min.js
  ```

  Sizes that match an OLD commit mean the metadata is stale. A SHA-pinned URL
  (`@<sha>/…`, immutable) is the ground truth and the escape hatch.
- The **loader rarely changes.** When it does, update it in BOTH places and purge
  both: `main`'s `panel.js` AND the `refs` branch's `heads/main/panel.js`.

  **Mirror with `git show`, NEVER with `cp`.** `git checkout refs` replaces the
  working tree with the `refs` branch, which has its OWN 1,872-byte root
  `panel.js` stub. `cp panel.js heads/main/panel.js` therefore copies that stub
  over the real loader and pushes it to the URL every bookmarklet fetches —
  which has already broken the live URL once.

  ```bash
  git checkout refs
  git show main:panel.js > heads/main/panel.js        # NOT cp
  git show main:panel.js > /tmp/lm; cmp -s heads/main/panel.js /tmp/lm && echo "identical? YES" || echo "identical? NO - STOP"
  git diff --stat                                      # expect a small edit, NOT "3 insertions, 291 deletions"
  git add heads/main/panel.js && git commit && git push origin refs
  git checkout main
  curl -s "https://purge.jsdelivr.net/gh/lucidium2000/TE-Optics@refs/heads/main/panel.js" -o /dev/null -w "%{http_code}\n"
  ```

  The `identical?` check and the `--stat` line are the two guards that catch a
  bad mirror before it ships. Run both, every time. A purge of this URL can
  need a second attempt — the first often returns `x-cache: HIT` on one tier.
- Verify the loader with:
  `curl -s https://cdn.jsdelivr.net/gh/lucidium2000/TE-Optics@refs/heads/main/panel.js`
  — expect HTTP 200, `application/javascript`, a body injecting
  `@main/panel.build.js`, and a byte count matching `wc -c < panel.js`.

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
- **No test suite / linter.** `node -c` on all four files is the check. For UI
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
