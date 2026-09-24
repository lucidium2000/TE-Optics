/*
 * TE Optics — browser bookmarklet / panel for ThousandEyes (app.thousandeyes.com).
 *
 * Copyright (c) 2026 Christopher G. Hunt.
 * Licensed under the MIT License — see LICENSE in the repository root.
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
/*
 * LOADER SHIM — this file exists only so the ORIGINAL bookmarklet URL
 * (…/panel.js, which everyone already has bookmarked) keeps working with the
 * same icon. It injects the minified build (panel.min.js) so existing users
 * download the smaller file without re-installing the bookmark.
 *
 * The real code lives in src/panel.js (source) → panel.min.js (built).
 * Do NOT put panel logic here. Edit src/panel.js and run `npm run build`.
 *
 * BOOT SKELETON. The build is ~330KB over the wire and on a slow link there was
 * nothing on screen for up to five seconds — no way to tell whether the click
 * had even registered. This file is small and arrives long before it, so it
 * paints a panel-shaped radar scope straight away and the wait reads as the
 * panel arriving rather than as nothing happening. CONFIRMED via user request.
 */

(function () {
  var D = document, BOOT = 'tep-boot';
  // A second click while the first load is in flight must not stack a second
  // skeleton or a second copy of the build.
  if (D.getElementById(BOOT)) return;

  // Every click is an UNCACHED round trip - the bookmarklet busts this file's
  // cache and this file busts the build's - so a single stalled request is the
  // difference between working and not. It is not slowness: the build is ~7KB
  // over the wire (1.4MB brotli'd) and compiles in milliseconds, so anything
  // that reaches the cutoff has stalled outright rather than crawled. Retry
  // once, automatically, which is exactly the thing that makes it work when a
  // user clicks the bookmarklet a second time. CONFIRMED via user report
  // ("getting this a lot today, sometimes it works").
  var tries = 0;
  function inject() {
    tries++;
    var s = D.createElement('script');
    s.src = 'https://cdn.jsdelivr.net/gh/lucidium2000/TE-Optics@main/panel.min.js?' + Date.now();
    s.onload = function () { loaded = true; paintStatus(); };
    s.onerror = function () { again('Could not reach the CDN'); };
    (D.body || D.documentElement).appendChild(s);
  }
  // A second attempt, or the failure card if we have already had one.
  function again(why) {
    if (done || failed) return;
    if (tries >= 2) { fail(why); return; }
    retrying = true; paintStatus();
    inject();
    if (timer) clearTimeout(timer);
    timer = setTimeout(function () { fail(why); }, RETRY_MS);
  }

  // Already up — this click is a toggle, which the build handles. A skeleton
  // here would just flash over a working panel.
  if (D.getElementById('te-panel-root')) { inject(); return; }

  // Match the panel's real geometry so the skeleton is the exact size and shape
  // of the thing that replaces it (width is the user's saved preference).
  var W = 576;
  try { W = parseInt(localStorage.getItem('tep-panel-width'), 10) || 576; } catch (e) {}
  if (W < 320) W = 320;

  var reduce = false;
  try { reduce = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches); } catch (e) {}

  // Theme. This rule is duplicated from src/panel.js on purpose: the skeleton
  // paints before the build exists, so it cannot ask the build what the theme
  // is. Light is the default and dark counts ONLY when someone actually clicked
  // the toggle (tep-theme-explicit), exactly as applyTheme() decides it --
  // otherwise a stale 'dark' left in storage by an older build would flash a
  // dark skeleton at someone whose panel then renders light.
  // applyTheme() sets data-tep-theme="light" for light and REMOVES the attribute
  // for dark, so a present attribute is authoritative but an absent one tells us
  // nothing (it also means "the build has not run on this page yet").
  var light = true;
  try {
    var attr = D.documentElement.getAttribute('data-tep-theme');
    if (attr === 'light') light = true;
    else light = !(localStorage.getItem('tep-theme-explicit') === '1'
                && localStorage.getItem('tep-theme') === 'dark');
  } catch (e) {}

  // Coarse Natural Earth land, simplified from the build's own basemap to ~7KB
  // so the shim stays small. Rendered inline (not a data: URI) because TE's
  // CSP img-src would have to allow data: for a background-image to paint.
  var MAP = '<svg viewBox="0 0 180 129" xmlns="http://www.w3.org/2000/svg" focusable="false" aria-hidden="true">'
    + '<path d="M115 38L113 40L114 42L110 40L108 39L110 36L106 34L105 31L104 30L104 26L106 24L104 16L106 15L110 18L110 20L107 19L109 23L109 21L110 22L111 20L112 20L112 17L113 17L113 19L117 16L117 17L119 16L120 17L120 15L124 17L123 13L125 10L126 10L126 20L128 18L127 13L127 10L128 13L129 11L131 12L130 9L133 8L134 6L140 4L142 1L144 3L146 3L147 5L145 8L147 8L147 10L148 9L152 10L152 9L153 9L156 14L156 12L160 13L160 10L165 11L166 14L169 14L170 16L174 15L175 17L175 15L180 16L180 21L179 22L180 24L177 25L175 27L172 27L171 32L168 35L168 30L172 24L170 26L170 25L168 25L167 28L161 28L158 32L160 32L161 34L160 37L157 41L155 41L156 39L158 37L156 37L152 33L150 33L149 36L144 36L139 34L139 36L136 35L134 36L130 35L128 32L127 33L125 31L121 32L121 35L115 34L114 35L113 37ZM29 36L26 35L25 31L22 27L21 28L20 26L20 15L22 16L26 14L27 16L28 15L28 16L29 15L32 16L33 18L36 18L36 17L37 17L39 18L41 17L42 19L43 16L42 15L42 12L46 19L47 15L49 17L49 19L47 19L43 26L44 30L49 31L50 35L50 32L52 30L51 24L53 24L55 26L56 29L58 26L59 30L62 34L56 36L54 38L58 36L58 38L60 38L60 39L57 40L58 39L56 39L55 38L54 39L49 42L49 39L46 37ZM67 0L84 0L80 0L81 0L80 0L81 2L79 3L80 8L79 8L80 9L78 10L79 11L78 11L79 14L77 13L77 14L79 15L70 21L68 27L65 25L64 22L63 19L65 15L63 15L63 14L64 14L62 12L63 11L61 5L59 4L56 4L54 2L57 1L53 0ZM130 41L130 39L134 36L135 39L138 41L145 41L146 39L150 38L148 37L150 35L150 33L153 33L156 37L158 37L155 41L149 43L151 44L150 46L151 50L145 54L143 53L141 54L140 53L139 50L138 49L134 50L129 48L129 46L127 43ZM29 36L46 37L49 39L49 42L54 39L55 38L57 39L52 43L52 44L51 44L52 45L49 48L50 52L48 49L47 49L43 49L41 51L37 48L31 47L30 46L28 42L28 37L29 38ZM153 82L149 83L148 83L147 76L150 75L153 72L155 72L156 70L158 70L158 72L160 74L161 70L163 74L167 78L165 85L162 86L160 85L159 83L158 83L159 82L158 83L156 81ZM63 82L61 80L63 78L61 76L61 73L57 69L55 70L53 68L55 67L55 64L57 64L58 63L58 62L60 62L60 64L64 62L65 64L70 66L73 68L71 71L70 76L66 77ZM20 15L20 26L21 28L22 27L25 32L23 29L19 27L16 26L14 28L15 25L11 31L8 32L12 28L9 28L7 26L7 25L10 23L10 22L8 22L6 21L8 19L9 20L7 16L12 13ZM134 36L130 39L130 41L127 40L124 42L122 40L119 39L118 39L118 42L116 41L115 40L117 38L114 38L113 37L115 34L121 35L121 32L125 31L127 33L128 32L130 35ZM61 80L61 83L62 84L57 87L58 88L56 90L57 91L55 94L56 95L54 95L53 93L56 77L57 76L61 77L61 79L63 78ZM51 11L53 13L54 12L56 15L57 16L56 17L59 19L58 21L56 20L58 23L58 24L56 23L57 25L53 22L51 22L53 21L54 19L51 15L45 14L46 9L47 9L47 11L49 9L50 12ZM139 50L136 53L136 52L134 51L134 53L130 57L129 61L126 54L124 52L126 52L125 51L128 47L127 46L129 46L129 48L131 49L130 50L132 50ZM134 36L136 35L139 36L139 34L144 36L148 36L148 37L150 38L142 42L138 41L135 39ZM86 50L89 47L89 45L94 45L95 51L96 52L92 55ZM31 47L40 49L41 51L42 55L46 53L46 55L44 55L44 57L38 55L33 48L33 49L35 53L32 50ZM105 67L105 71L101 70L101 68L96 68L98 66L100 62L105 62L106 63ZM107 49L110 48L114 50L116 53L118 53L118 54L111 56ZM114 49L112 43L114 43L116 45L119 44L121 45L120 49L122 51L121 52L119 51ZM95 28L96 22L98 18L100 16L102 18L102 20L99 24L99 27L98 31L96 31ZM103 53L102 55L95 52L95 48L96 47L100 49L100 47L102 48ZM37 10L39 15L39 17L33 17L31 15L34 14L31 14L32 13L30 12L31 11L32 10L33 11L35 10L36 12L36 10ZM102 60L101 58L103 53L108 53L109 55L107 60L106 58L106 60L103 59ZM104 16L106 24L104 26L101 27L101 24L103 21L100 16L102 17L104 15ZM106 15L104 16L104 15L102 17L101 16L100 17L99 17L96 23L95 28L93 28L93 25L100 15L104 13L106 14ZM98 79L100 79L100 77L101 78L105 76L106 77L105 78L106 78L104 82L100 83ZM102 55L101 59L98 61L97 57L97 53ZM55 67L53 68L56 71L55 74L52 72L49 67L50 67L52 65ZM84 58L84 57L87 57L87 52L92 55L92 57L88 58L87 59ZM106 34L110 36L108 39L106 38L104 39L104 37L101 37L102 34ZM97 53L97 58L91 58L90 57L92 57L92 55L96 52ZM96 68L101 68L102 71L101 71L102 73L96 73L97 71ZM112 44L105 45L103 43L107 41L111 42ZM108 53L103 53L103 48L107 48L107 50L106 49ZM55 73L57 76L55 81L53 93L54 95L56 95L54 97L53 95L52 91L54 88L53 89L53 85ZM81 54L84 54L84 51L86 51L86 50L88 52L87 52L87 57L82 56ZM55 70L57 69L61 73L61 75L59 75L59 76L56 76ZM93 36L94 36L93 38L94 40L89 41L89 39L88 37L89 37L89 36L91 35ZM57 64L55 64L55 67L51 64L51 60L54 58L53 60L56 61ZM117 9L119 5L124 2L124 4L119 8L118 11L119 14L116 13ZM129 46L127 46L128 47L125 51L126 52L121 52L122 51L120 49L123 49L126 45ZM114 60L110 63L106 61L109 57L111 58L112 60ZM100 77L100 79L98 79L96 73L103 73L100 74ZM123 44L125 44L126 45L128 45L126 45L123 49L120 49L121 45ZM107 65L110 67L110 70L107 70L105 68L105 65ZM46 8L44 7L42 2L44 3L45 5L49 5L50 7ZM91 61L92 58L97 58L94 62ZM60 62L58 62L58 63L57 64L56 61L54 61L54 59L54 60L55 58L59 59L60 60ZM97 32L96 38L94 37L93 34L94 32ZM107 70L110 70L110 72L107 75L108 77L106 78L106 73L105 72L107 72L108 73ZM44 0L59 0L52 0L50 4L45 3L46 0L48 1L46 0L49 0ZM86 45L87 42L85 41L86 40L92 41L89 45ZM29 7L32 9L28 14L27 12L28 8ZM118 42L118 39L119 39L122 40L123 42L125 41L127 42L124 43L124 44L119 41ZM102 32L101 36L97 35L97 32L99 32ZM105 69L107 69L107 72L104 74L102 73L101 71L102 70L105 71L104 69ZM89 46L89 47L81 54L87 45ZM116 41L119 42L119 41L123 44L121 46L119 44L117 44L116 43L117 42ZM140 54L139 55L139 60L139 56L137 56L136 54L139 50L139 52L141 53ZM36 5L37 4L37 6L34 8L33 7L34 6L31 6L32 3L35 5L35 3ZM3 19L3 20L3 19L4 19L5 20L4 22L1 20L0 21L0 16ZM105 76L100 78L100 74L103 74ZM88 33L87 31L87 28L88 28L88 31L91 33L90 35L87 36ZM115 71L115 72L113 78L112 76L112 73ZM105 63L102 60L103 59L106 60L106 58L106 61L108 62ZM104 62L100 62L98 63L97 62L98 61L101 59ZM110 48L111 45L112 44L114 49L112 49ZM110 67L107 65L108 62L111 63ZM83 20L83 21L81 23L78 22L79 21L78 20L80 21ZM104 30L105 31L106 34L102 34L102 32ZM143 57L141 57L141 58L140 58L140 60L141 62L139 61L139 54L140 54L140 56L142 55ZM149 62L149 64L148 67L145 66L145 64L147 64ZM95 38L97 38L96 40L99 43L98 42L98 44L95 40L94 40L93 39ZM104 39L104 40L101 40L100 39L103 37ZM111 65L111 62L116 58L114 62ZM116 55L116 57L112 58L112 56ZM61 75L63 77L62 79L61 79L61 77L59 76L59 75ZM97 58L98 64L95 63L95 61L96 61ZM161 43L160 46L156 47L155 48L155 47L160 44L160 42ZM142 65L143 66L142 68L138 62ZM159 4L163 5L162 7L159 7L158 6ZM106 76L103 74L106 73ZM160 66L164 68L165 70L162 68L161 69ZM160 66L161 69L159 69L159 67L157 67L156 66L157 66L155 65L157 65L158 66L159 65ZM40 11L40 9L41 9L42 12L40 13L39 11ZM142 59L144 58L141 53L143 53L144 53L143 55L145 59L143 60ZM118 53L118 52L120 53L117 56L116 55L118 54ZM125 41L130 41L126 43L125 43L127 42ZM99 63L98 66L96 67L96 66L97 65L97 63ZM86 59L89 60L89 62L86 62ZM29 4L30 1L32 1L31 3ZM41 3L41 6L40 7L39 4ZM43 8L45 9L43 12L42 10ZM175 89L177 87L175 91L173 90ZM87 59L90 57L91 58ZM62 35L62 36L63 36L63 38L63 37L60 37ZM108 47L108 45L111 44L111 46ZM96 63L97 64L97 65L96 67L94 65ZM144 57L143 57L142 55L140 56L141 53ZM90 59L91 62L89 62L89 59ZM52 65L50 67L50 64ZM107 65L105 65L105 63L107 63ZM61 80L63 81L63 83L61 83ZM83 58L86 58L86 61L84 59L83 60L82 59ZM98 0L101 0L100 0L98 3L97 1L95 0ZM95 49L94 47L95 44L96 47ZM124 44L124 43L125 42L125 43L127 43L128 44L126 45L125 44ZM48 21L50 23L46 23L47 21ZM155 41L154 44L153 44L152 43ZM62 64L60 64L59 62L60 60ZM82 58L81 57L83 56L84 58ZM104 29L104 30L103 31L101 31L101 29ZM102 42L103 42L101 42L102 44L101 45L100 43ZM149 62L147 64L145 64L148 61L150 62ZM161 33L162 36L161 39ZM101 40L104 40L104 41L102 42ZM101 37L100 39L98 38L98 37ZM178 86L177 87L176 83L179 85ZM103 31L102 32L101 31ZM97 35L99 36L97 37L96 35ZM141 58L141 57L144 57L143 59ZM134 50L134 51L130 50L131 49ZM151 64L150 65L152 65L151 66L152 67L150 66L150 67L150 64ZM56 96L56 98L53 96L54 97ZM98 37L97 38L95 38L97 36ZM162 40L160 42L161 39ZM114 59L114 60L111 59ZM104 27L104 29L102 29L102 28ZM86 41L87 42L86 45Z"/></svg>';

  var css = D.createElement('style');
  css.id = BOOT + '-css';
  css.textContent = [
    // ── Shell ───────────────────────────────────────────────────────────────
    '#B{position:fixed;top:0;right:0;height:100vh;width:' + W + 'px;z-index:2147483646;',
    'background:#0f172a;border-left:1px solid #334155;box-shadow:-4px 0 20px rgba(0,0,0,.4);',
    "font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;flex-direction:column;",
    'overflow:hidden;transform:translateX(100%);transition:transform .3s cubic-bezier(.22,.88,.36,1),opacity .22s ease;box-sizing:border-box}',
    '#B.in{transform:translateX(0)}#B.out{opacity:0}',
    // A faint technical grid behind everything — reads as instrument, not chrome.
    '#B::before{content:"";position:absolute;inset:0;pointer-events:none;',
    'background-image:linear-gradient(rgba(148,163,184,.04) 1px,transparent 1px),',
    'linear-gradient(90deg,rgba(148,163,184,.04) 1px,transparent 1px);background-size:24px 24px}',
    // A scanline drifting down the whole panel.
    '#B .bscan{position:absolute;left:0;right:0;height:80px;pointer-events:none;z-index:2;',
    'background:linear-gradient(180deg,transparent,rgba(249,115,22,.05),transparent);animation:tepscan 4.2s linear infinite}',
    '@keyframes tepscan{0%{top:-80px}100%{top:100%}}',
    // ── Header: the panel's own pinned navy, same 56px, so the swap is seamless.
    '#B .bh{position:relative;z-index:3;height:56px;flex:0 0 auto;display:flex;align-items:center;gap:10px;',
    'padding:0 16px;background:#0b1f3a;border-bottom:1px solid #14274e;box-sizing:border-box}',
    '#B .bt{font-size:14px;font-weight:800;letter-spacing:-.01em;color:#f1f5f9}',
    '#B .bv{margin-left:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9.5px;',
    'font-weight:700;letter-spacing:.14em;color:#475569;text-transform:uppercase}',
    // Header mark: a miniature of the scope, sweeping in step with it.
    '#B .bm{width:18px;height:18px;flex:0 0 auto;position:relative;border-radius:50%;',
    'box-shadow:inset 0 0 0 1px rgba(249,115,22,.45);overflow:hidden}',
    '#B .bm::after{content:"";position:absolute;inset:0;border-radius:50%;',
    'background:conic-gradient(from 0deg,rgba(249,115,22,.95) 0deg,rgba(249,115,22,.12) 30deg,transparent 70deg);',
    'animation:tepsweep DURs linear infinite}',
    // Indeterminate sweep under the header. No real percentage is available:
    // TE's CSP connect-src blocks fetch() to the CDN, so the bytes cannot be
    // counted — better an honest indeterminate bar than a fake one.
    '#B .bp{position:relative;z-index:3;height:2px;flex:0 0 auto;background:#111c30;overflow:hidden}',
    '#B .bp i{position:absolute;top:0;bottom:0;width:38%;',
    'background:linear-gradient(90deg,transparent,#f97316,#fdba74,transparent);animation:tepbar 1.35s ease-in-out infinite}',
    '@keyframes tepbar{0%{left:-40%}100%{left:102%}}',
    // ── Body ────────────────────────────────────────────────────────────────
    '#B .bb{position:relative;z-index:3;flex:1 1 auto;padding:22px 16px 14px;display:flex;flex-direction:column;gap:11px;overflow:hidden}',
    // Scope + its HUD frame.
    '#B .bw{position:relative;flex:0 0 auto;width:150px;height:150px;margin:2px auto 6px}',
    '#B .br{position:absolute;inset:0;border-radius:50%;overflow:hidden;background:#0a1322;',
    'box-shadow:inset 0 0 0 1px #24324d,inset 0 0 26px -6px rgba(249,115,22,.35),0 0 38px -10px rgba(249,115,22,.55)}',
    // Terrain under the beam: one world strip rendered twice and drifted by
    // exactly one copy, so the loop is seamless (the map repeats every 360deg).
    '#B .bmap{position:absolute;inset:0;overflow:hidden;border-radius:50%}',
    '#B .bmapi{position:absolute;top:50%;left:0;display:flex;width:660px;height:236px;',
    'transform:translate(0,-50%);animation:tepdrift 48s linear infinite}',
    '#B .bmapi svg{flex:0 0 330px;width:330px;height:236px;display:block}',
    '#B .bmapi path{fill:#2f4a6b;stroke:#2f4a6b;stroke-width:1.4;stroke-linejoin:round}',
    '@keyframes tepdrift{to{transform:translate(-330px,-50%)}}',
    // A lens tint over the terrain so it sits behind the instrument, not in it.
    '#B .br::after{content:"";position:absolute;inset:0;border-radius:50%;pointer-events:none;',
    'background:radial-gradient(circle at 50% 50%,rgba(249,115,22,.1),rgba(10,19,34,.55) 78%)}',
    // Range rings.
    '#B .brx::before,#B .brx::after{content:"";position:absolute;border-radius:50%;',
    'border:1px solid rgba(203,213,225,.16)}',
    '#B .brx::before{inset:17%}#B .brx::after{inset:34%}',
    // Degree ticks around the rim, masked to a thin annulus.
    '#B .brt{position:absolute;inset:0;border-radius:50%;',
    'background:repeating-conic-gradient(from 0deg,rgba(148,163,184,.34) 0deg 1deg,transparent 1deg 15deg);',
    '-webkit-mask:radial-gradient(circle,transparent 0 45%,#000 45% 50%,transparent 50%);',
    'mask:radial-gradient(circle,transparent 0 45%,#000 45% 50%,transparent 50%)}',
    '#B .brx{position:absolute;inset:0}',
    '#B .brc{position:absolute;inset:0}',
    '#B .brc::before,#B .brc::after{content:"";position:absolute;background:rgba(203,213,225,.14)}',
    '#B .brc::before{left:7%;right:7%;top:50%;height:1px}',
    '#B .brc::after{top:7%;bottom:7%;left:50%;width:1px}',
    '#B .brs{position:absolute;inset:0;border-radius:50%;overflow:hidden}',
    '#B .brs::before{content:"";position:absolute;inset:0;border-radius:50%;',
    'background:conic-gradient(from 0deg,rgba(249,115,22,.62) 0deg,rgba(249,115,22,.16) 30deg,transparent 68deg);',
    'animation:tepsweep DURs linear infinite}',
    // Bright leading edge, so it reads as a beam sweeping rather than a wedge turning.
    '#B .brl{position:absolute;left:50%;top:8%;bottom:50%;width:1px;transform-origin:50% 100%;',
    'background:linear-gradient(180deg,rgba(253,186,116,0),rgba(253,186,116,.95));',
    'box-shadow:0 0 6px rgba(253,186,116,.7);animation:tepsweep DURs linear infinite}',
    '#B .brb i{position:absolute;width:5px;height:5px;margin:-2.5px 0 0 -2.5px;border-radius:50%;',
    'background:#fdba74;box-shadow:0 0 10px 1px rgba(253,186,116,.9);opacity:0;animation:tepblip DURs linear infinite}',
    '@keyframes tepsweep{to{transform:rotate(360deg)}}',
    '@keyframes tepblip{0%{opacity:0}2%{opacity:1}20%{opacity:0}100%{opacity:0}}',
    // Status line — monospace with a blinking caret.
    '#B .bst{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;letter-spacing:.03em;',
    'text-align:center;color:#fdba74;flex:0 0 auto;min-height:15px}',
    '#B .bst u{text-decoration:none;color:#64748b}',
    '#B .bck{margin:7px 18px 0;display:none}#B .bck.on{display:block}',
    '#B .bcr{display:flex;gap:2px}',
    '#B .bcs{flex:1;text-align:center;position:relative;font-family:ui-monospace,Menlo,monospace}',
    '#B .bcs::before{content:"";position:absolute;left:-50%;top:4px;width:100%;height:1px;background:#1e293b}',
    '#B .bcs:first-child::before{display:none}',
    '#B .bcd{width:9px;height:9px;border-radius:50%;margin:0 auto 4px;background:#334155;position:relative;z-index:1}',
    '#B .bcs.ok .bcd{background:#22c55e;box-shadow:0 0 7px rgba(34,197,94,.5)}',
    '#B .bcs.wa .bcd{background:#f59e0b;box-shadow:0 0 7px rgba(245,158,11,.5)}',
    '#B .bcs.ba .bcd{background:#ef4444;box-shadow:0 0 7px rgba(239,68,68,.5)}',
    '#B .bcn{font-size:8px;letter-spacing:.06em;color:#64748b;text-transform:uppercase}',
    '#B .bcv{font-size:10px;font-weight:700;color:#cbd5e1}',
    '#B .bcm{margin-top:7px;font-size:10px;color:#64748b;text-align:center;line-height:1.4}',
    '#B .bsx{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:9.5px;letter-spacing:.04em;',
    'color:#475569;text-align:center;margin-top:3px;min-height:12px;text-transform:uppercase}',
    '#B .bcar{display:inline-block;width:6px;height:11px;vertical-align:-1px;margin-left:4px;',
    'background:#fdba74;animation:tepcar 1.05s steps(1) infinite}',
    '@keyframes tepcar{50%{opacity:0}}',
    // Skeleton cards.
    '#B .bc{border:1px solid #1e293b;border-radius:8px;background:#131f38;padding:11px 13px;display:flex;flex-direction:column;gap:8px}',
    '#B .bl{height:9px;border-radius:5px;background:#1e293b;position:relative;overflow:hidden}',
    '#B .bl::after{content:"";position:absolute;inset:0;transform:translateX(-100%);',
    'background:linear-gradient(90deg,transparent,rgba(148,163,184,.16),transparent);animation:tepsh 1.6s infinite}',
    '@keyframes tepsh{100%{transform:translateX(100%)}}',
    '#B .bf{margin-top:auto;font-size:11px;color:#64748b;text-align:center;padding-bottom:4px}',
    '#B .be{color:#fca5a5}',
    '#B.err .bm::after,#B.err .brs::before,#B.err .brl,#B.err .brb i,#B.err .bp i,'
    + '#B.err .bl::after,#B.err .bscan{animation-play-state:paused;opacity:.25}',
    '#B.err .bmapi{animation-play-state:paused}',
    '#B.err .br{filter:grayscale(1) brightness(.72);box-shadow:inset 0 0 0 1px #24324d}',
    '#B.err .bt{color:#94a3b8}',
    // Placeholder rows promise content that is not coming; drop them so the
    // message and the retry button fit even in a short viewport.
    '#B.err .bc{display:none}',
    '#B.err .bv{color:#b45309}',
    '#B .bx{margin-top:10px;flex:0 0 auto;align-self:center;font:inherit;font-size:12px;font-weight:700;cursor:pointer;',
    'color:#fdba74;background:rgba(249,115,22,.16);border:1px solid #f97316;border-radius:7px;padding:5px 13px}',
    reduce ? '#B .bm::after,#B .brs::before,#B .brl,#B .brb i,#B .bp i,#B .bl::after,#B .bscan,#B .bmapi,#B .bcar{animation:none}' : '',
    // Light theme. The header is deliberately untouched: the build pins it to
    // the same navy in BOTH themes so it sits flush against TE's own navy top
    // bar, and the scope is an instrument (like .tep-dashmap-full, which opts
    // out of the toggle entirely), so only the surrounding chrome flips.
    !light ? '' : [
      '#B.lt{background:#f4f5f7;border-left-color:#e1e4e8;box-shadow:-4px 0 20px rgba(15,23,42,.13)}',
      '#B.lt::before{background-image:linear-gradient(rgba(100,116,139,.07) 1px,transparent 1px),',
      'linear-gradient(90deg,rgba(100,116,139,.07) 1px,transparent 1px)}',
      '#B.lt .bscan{background:linear-gradient(180deg,transparent,rgba(180,83,9,.05),transparent)}',
      '#B.lt .bp{background:#e6e9ec}',
      '#B.lt .bp i{background:linear-gradient(90deg,transparent,#b45309,#f59e0b,transparent)}',
      '#B.lt .br{box-shadow:inset 0 0 0 1px #24324d,inset 0 0 26px -6px rgba(249,115,22,.35),',
      '0 0 0 1px rgba(15,23,42,.1),0 8px 20px -8px rgba(15,23,42,.5)}',
      '#B.lt .bst{color:#c2410c}#B.lt .bst u{color:#78838f}#B.lt .bcar{background:#c2410c}',
      '#B.lt .bsx{color:#8b95a1}#B.lt .bcn{color:#8b95a1}#B.lt .bcv{color:#334155}',
      '#B.lt .bcm{color:#5f6b77}#B.lt .bcd{background:#cbd5e1}#B.lt .bcs::before{background:#d7dce2}',
      '#B.lt .bc{background:#fff;border-color:#e1e4e8}',
      '#B.lt .bl{background:#e8ebee}',
      '#B.lt .bl::after{background:linear-gradient(90deg,transparent,rgba(15,23,42,.07),transparent)}',
      '#B.lt .bf{color:#5f6b77}#B.lt .be{color:#b91c1c}',
      '#B.lt .bx{color:#b45309;background:rgba(180,83,9,.1);border-color:#b45309}',
      // The scope flips too: a daylight chart rather than a dark screen, with
      // the beam re-cut in the light theme's deeper orange so it still reads
      // against a pale ground.
      '#B.lt .br{background:#e9edf2;box-shadow:inset 0 0 0 1px rgba(15,23,42,.18),',
      'inset 0 0 26px -8px rgba(180,83,9,.3),0 0 0 1px rgba(15,23,42,.06),0 8px 20px -10px rgba(15,23,42,.4)}',
      '#B.lt .bmapi path{fill:#b3c1d3;stroke:#b3c1d3}',
      '#B.lt .brt{background:repeating-conic-gradient(from 0deg,rgba(71,85,105,.42) 0deg 1deg,transparent 1deg 15deg)}',
      '#B.lt .brx::before,#B.lt .brx::after{border-color:rgba(51,65,85,.22)}',
      '#B.lt .brc::before,#B.lt .brc::after{background:rgba(51,65,85,.2)}',
      '#B.lt .brs::before{background:conic-gradient(from 0deg,rgba(180,83,9,.5) 0deg,rgba(180,83,9,.14) 30deg,transparent 68deg)}',
      '#B.lt .brl{background:linear-gradient(180deg,rgba(194,65,12,0),rgba(194,65,12,.95));',
      'box-shadow:0 0 6px rgba(194,65,12,.55)}',
      '#B.lt .brb i{background:#c2410c;box-shadow:0 0 9px 1px rgba(194,65,12,.8)}',
      '#B.lt .br::after{background:radial-gradient(circle at 50% 50%,rgba(180,83,9,.09),rgba(226,232,240,.5) 78%)}'
    ].join('')
  ].join('').replace(/#B\b/g, '#' + BOOT).replace(/DURs/g, '2.6s');

  var el = D.createElement('div');
  el.id = BOOT;
  if (light) el.className = 'lt';
  el.setAttribute('role', 'status');
  el.setAttribute('aria-live', 'polite');
  var card = '<div class="bc"><div class="bl"></div><div class="bl" style="width:62%"></div></div>';
  el.innerHTML =
    '<span class="bscan"></span>'
    + '<div class="bh"><span class="bm"></span><span class="bt">Loading TE Optics…</span>'
    + '<span class="bv" id="' + BOOT + '-el">0.0s</span></div>'
    + '<div class="bp"><i></i></div>'
    + '<div class="bb">'
    + '<div class="bw"><span class="br"><span class="bmap"><span class="bmapi">' + MAP + MAP + '</span></span>'
    + '<span class="brt"></span><span class="brx"></span><span class="brc"></span>'
    + '<span class="brs"></span><span class="brl"></span>'
    + '<span class="brb"><i style="left:73.0%;top:29.3%;animation-delay:0.35s"></i><i style="left:63.9%;top:63.0%;animation-delay:0.96s"></i><i style="left:30.4%;top:79.0%;animation-delay:1.55s"></i><i style="left:29.8%;top:33.6%;animation-delay:2.23s"></i></span></span></div>'
    + '<div class="bst" id="' + BOOT + '-st"></div>'
    + '<div class="bsx" id="' + BOOT + '-sx"></div>'
    + '<div class="bck" id="' + BOOT + '-ck"></div>'
    + card + card
    + '<div class="bf" id="' + BOOT + '-f"></div></div>';

  (D.body || D.documentElement).appendChild(css);
  (D.body || D.documentElement).appendChild(el);
  // Next frame, so the translateX(100%) start state actually paints and the
  // slide-in runs instead of being coalesced away.
  requestAnimationFrame(function () { requestAnimationFrame(function () { el.classList.add('in'); }); });

  // Status line. These are the real phases: the CDN request goes out, the build
  // downloads, and past a few seconds it is simply slow. Nothing here claims a
  // percentage, because none is knowable (see the progress bar note above).
  var stEl = D.getElementById(BOOT + '-st'), elEl = D.getElementById(BOOT + '-el'),
      sxEl = D.getElementById(BOOT + '-sx'), t0 = Date.now();
  // Three things here are genuinely observable, so the status reports only
  // those and still never invents a percentage (see the progress bar note
  // above - the sweep stays indeterminate because no fraction is knowable):
  //   1. whether there is a connection at all,
  //   2. whether the build's script has finished loading and running,
  //   3. how jsDelivr is behaving RIGHT NOW - which is free, because the
  //      bookmarklet pulled THIS file from the same CDN a moment ago, so its
  //      Resource Timing entry is a real measurement rather than a guess.
  var loaded = false;
  function isOnline() { try { return navigator.onLine !== false; } catch (e) { return true; } }
  function conn() {
    try { return navigator.connection || navigator.mozConnection || navigator.webkitConnection || null; }
    catch (e) { return null; }
  }
  // Slowest completed jsDelivr request so far: this loader's own fetch to begin
  // with, then the build's once it lands.
  function cdnMs() {
    var e = entryFor('cdn.jsdelivr.net');
    return e ? Math.round(e.duration) : null;
  }
  // ── Connection check ────────────────────────────────────────────────────
  // NOT a traceroute: a browser has no raw sockets and no TTL control, so no
  // page can produce a hop list. This is the real connection to the CDN split
  // into the stages the Resource Timing API actually measures, which is what
  // says WHERE a slow load went slow. jsDelivr sends Timing-Allow-Origin: *,
  // so the detailed cross-origin timings are ours to read instead of zeroed.
  var ckEl = D.getElementById(BOOT + '-ck'), ckDone = false;
  // Entries are collected by an OBSERVER, not read out of the buffer. The
  // resource buffer holds 250 entries and a heavy SPA fills it long before
  // anyone clicks a bookmarklet; once full the browser silently stops recording,
  // so getEntriesByType('resource') can return nothing at all for our own
  // fetches. An observer is still delivered every new entry regardless, and
  // buffered:true also hands us whatever is still in the buffer - including
  // this loader's own fetch, which happened before we could observe anything.
  var seenRes = [];
  try {
    var po = new PerformanceObserver(function (list) {
      var es = list.getEntries();
      for (var i = 0; i < es.length; i++) if (es[i].duration > 0) seenRes.push(es[i]);
      if (seenRes.length > 60) seenRes = seenRes.slice(-60);
    });
    po.observe({ type: 'resource', buffered: true });
  } catch (e) { /* older engine - fall back to the buffer below */ }
  function entryFor(host) {
    if (!host) return null;
    var pool = seenRes;
    try {
      if (!pool.length) pool = performance.getEntriesByType('resource');
    } catch (e) { /* */ }
    var best = null;
    for (var i = 0; i < pool.length; i++) {
      var e = pool[i];
      if (!e || !e.name || e.name.indexOf(host) < 0 || !(e.duration > 0)) continue;
      if (!best || e.startTime > best.startTime) best = e;
    }
    return best;
  }
  // thresholds: [good, bad] ms per stage
  var LIM = { dns: [40, 200], tcp: [80, 300], tls: [80, 300], ttfb: [150, 600], xfer: [100, 500] };
  function msFmt(v) { return v < 1 ? '<1ms' : v < 1000 ? Math.round(v) + 'ms' : (v / 1000).toFixed(1) + 's'; }
  function kb(v) { return v < 1024 ? v + 'B' : (v / 1024).toFixed(1) + 'KB'; }
  function renderCheck() {
    if (!ckEl) return;
    var e = entryFor('cdn.jsdelivr.net');
    if (!e) return;
    var tls = e.secureConnectionStart > 0 ? e.connectEnd - e.secureConnectionStart : 0;
    // A reused connection reports connectStart === connectEnd; the zeros are
    // real and worth saying out loud rather than drawing as instant stages.
    var fresh = e.connectEnd > e.connectStart;
    var st = [
      ['dns',  e.domainLookupEnd - e.domainLookupStart],
      ['tcp',  (e.connectEnd - e.connectStart) - tls],
      ['tls',  tls],
      ['ttfb', e.responseStart - e.requestStart],
      ['xfer', e.responseEnd - e.responseStart]
    ];
    var row = '';
    for (var i = 0; i < st.length; i++) {
      var k = st[i][0], v = Math.max(0, st[i][1]), L = LIM[k];
      var cls = (!fresh && (k === 'dns' || k === 'tcp' || k === 'tls')) ? ''
        : v <= L[0] ? 'ok' : v <= L[1] ? 'wa' : 'ba';
      row += '<div class="bcs ' + cls + '"><div class="bcd"></div>'
        + '<div class="bcn">' + k + '</div><div class="bcv">'
        + ((!fresh && cls === '') ? '\u2014' : msFmt(v)) + '</div></div>';
    }
    // The control: is it the CDN, or is everything slow? The app's own origin
    // is same-origin, so its timings need no opt-in.
    var app = entryFor(location.hostname), note = '';
    var SLOW = 400;   // ms: below this nothing here is worth calling a problem
    if (!fresh) note = 'Connection reused \u2014 no new DNS, TCP or TLS needed.';
    else if (!app) note = '';
    // Only draw a conclusion when one side is ACTUALLY slow. Saying "the link is
    // the common factor" because a healthy 130ms beat a healthy 110ms is noise
    // dressed up as a diagnosis.
    else if (e.duration > SLOW && e.duration > app.duration * 2) {
      note = location.hostname + ' answered in ' + msFmt(app.duration) + ', so the CDN is the slow side.';
    } else if (app.duration > SLOW && app.duration > e.duration * 2) {
      note = location.hostname + ' is slower still (' + msFmt(app.duration) + ') \u2014 the link is the common factor.';
    } else if (e.duration > SLOW) {
      note = location.hostname + ' answered in ' + msFmt(app.duration) + ' \u2014 both are slow.';
    } else {
      note = 'For comparison, ' + location.hostname + ' answered in ' + msFmt(app.duration) + '.';
    }
    ckEl.innerHTML = '<div class="bcr">' + row + '</div><div class="bcm">'
      + 'Total ' + msFmt(e.duration) + ' \u00b7 ' + kb(e.transferSize || e.encodedBodySize || 0)
      + (e.nextHopProtocol ? ' \u00b7 ' + e.nextHopProtocol : '')
      + (note ? '<br>' + note : '') + '</div>';
    ckEl.className = 'bck on';
    ckDone = true;
  }
  var PHASES = [
    [0,    'Checking for updates'],
    [1500, 'Loading panel']
  ];
  var retrying = false;
  function paintStatus() {
    if (!stEl) return;
    var ms = Date.now() - t0, txt = PHASES[0][1];
    for (var i = 0; i < PHASES.length; i++) if (ms >= PHASES[i][0]) txt = PHASES[i][1];
    // Real state beats the clock wherever we have it.
    if (!isOnline()) txt = 'No connection';
    else if (loaded) txt = 'Starting panel';
    else if (retrying) txt = 'Retrying';
    else if (ms >= 2500) txt = 'CDN is slow';
    stEl.innerHTML = txt + '<u>…</u><span class="bcar"></span>';
    if (elEl) elEl.textContent = (ms / 1000).toFixed(1) + 's';
    if (!ckDone && ms >= 2500) renderCheck();
    if (sxEl) {
      var bits = [];
      if (!isOnline()) bits.push('offline');
      var d = cdnMs();
      if (d != null) bits.push('cdn ' + (d < 1000 ? d + 'ms' : (d / 1000).toFixed(1) + 's'));
      var c = conn();
      if (c && c.effectiveType && c.effectiveType !== '4g') bits.push('link ' + c.effectiveType);
      if (tries > 1) bits.push('attempt ' + tries + ' of 2');
      sxEl.textContent = bits.join('  \u00b7  ');
    }
  }
  paintStatus();
  var tick = setInterval(paintStatus, 100);

  // First attempt gets a shorter fuse than the old flat 8s, because the retry
  // now costs almost nothing; the second gets longer, since by then a slow link
  // is the likeliest explanation left.
  var FIRST_MS = 6000, RETRY_MS = 12000;
  var done = false, failed = false, timer = null;
  function stop() { if (timer) clearTimeout(timer); clearInterval(tick); }
  function kill() {
    try { el.remove(); } catch (e) {}
    try { css.remove(); } catch (e) {}
  }
  function finish() {
    if (done) return;
    done = true; stop();
    try { obs.disconnect(); } catch (e) {}
    el.classList.add('out');
    setTimeout(kill, 240);
  }
  // The 8s cutoff is a guess about a slow link, not proof the build is gone, so
  // the observer below deliberately stays connected: a build that shows up at
  // 9s clears this card instead of leaving it stranded over a working panel.
  function fail(why) {
    if (done || failed) return;
    failed = true; stop();
    el.classList.add('err');
    if (stEl) stEl.innerHTML = '';
    var t = el.querySelector('.bt'); if (t) t.textContent = 'TE Optics didn\u2019t load';
    var v = el.querySelector('.bv'); if (v) v.textContent = 'failed';
    var f = D.getElementById(BOOT + '-f');
    if (f) {
      f.className = 'bf be';
      // Name the cause rather than the symptom. These three are distinguishable
      // and mean completely different things to whoever has to fix it.
      var cause = !isOnline() ? 'You appear to be offline'
        : loaded ? 'The panel downloaded but did not start'
        : why + ' after two attempts';
      // Label the number for what it actually is - the slowest COMPLETED
      // jsDelivr request, which early on is this loader's own fetch. Calling it
      // "the CDN responded in 41ms" right under "could not reach the CDN" reads
      // as a contradiction when it is really the useful part: the connection
      // was fine, so the build request specifically is what went wrong.
      ckDone = false; renderCheck();   // refresh with whatever the last attempt measured
      var d = isOnline() ? cdnMs() : null;
      f.textContent = cause + '.'
        + (d != null ? ' Slowest CDN request: ' + (d < 1000 ? d + 'ms' : (d / 1000).toFixed(1) + 's') + '.' : '');
      var r = D.createElement('button');
      var b = D.createElement('button');
      function restart() {
        if (done || !failed) return;
        failed = false; tries = 0; loaded = false; retrying = false;
        el.classList.remove('err');
        var tt = el.querySelector('.bt'); if (tt) tt.textContent = 'TE Optics';
        var vv = el.querySelector('.bv'); if (vv) vv.textContent = 'loading';
        f.className = 'bf'; f.textContent = '';
        try { r.remove(); } catch (e) {}
        try { b.remove(); } catch (e) {}
        t0 = Date.now();
        tick = setInterval(paintStatus, 100); paintStatus();
        inject();
        timer = setTimeout(function () { again('Taking longer than expected'); }, FIRST_MS);
      }
      // Came back online while the failure card was up: just go, rather than
      // making someone who already knows their wifi dropped click anything.
      try { window.addEventListener('online', restart); } catch (e) {}
      r.className = 'bx'; r.textContent = 'Try again';
      r.onclick = restart;
      b.className = 'bx'; b.textContent = 'Dismiss';
      b.onclick = function () {
        done = true;
        try { window.removeEventListener('online', restart); } catch (e) {}
        try { obs.disconnect(); } catch (e) {} kill();
      };
      f.parentNode.appendChild(r);
      f.parentNode.appendChild(b);
    }
  }

  // The build renders #te-panel-root; that is the signal it is up. Watching the
  // DOM rather than the script's own onload means a build that is slow to render
  // still keeps the skeleton on screen until there is something to see.
  //
  // Self-removal matters: THIS file is cached for 7 days while the build ships in
  // minutes, so the two halves must never need to agree on anything — otherwise
  // an old cached build would strand the skeleton on screen. It also means the
  // loader and the build can ship in either order.
  var obs = new MutationObserver(function () {
    if (D.getElementById('te-panel-root')) finish();
  });
  try { obs.observe(D.documentElement, { childList: true, subtree: true }); } catch (e) {}

  timer = setTimeout(function () { again('Taking longer than expected'); }, FIRST_MS);

  inject();
})();
