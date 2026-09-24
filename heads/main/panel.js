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
 */
(function () {
  var s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/gh/lucidium2000/TE-Optics@main/panel.min.js?' + Date.now();
  (document.body || document.documentElement).appendChild(s);
})();
