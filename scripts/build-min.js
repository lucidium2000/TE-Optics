#!/usr/bin/env node
/*
 * Builds panel.min.js from src/panel.js — strips comments + whitespace only.
 * Identifiers and syntax are left untouched (minifyIdentifiers/minifySyntax
 * off) so the output is byte-for-byte semantically identical to the source,
 * just smaller. The leading license/disclaimer banner is preserved verbatim.
 *
 * Usage: node scripts/build-min.js   (or: npm run build)
 */
const esbuild = require('esbuild');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const srcPath = path.join(root, 'src', 'panel.js');
const outPath = path.join(root, 'panel.min.js');
// The SAME bytes, under a name jsDelivr cannot synthesise. jsDelivr generates a
// missing X.min.js by running Terser over X.js — and when its file metadata for
// the branch went stale it did exactly that, serving a minified copy of the
// LOADER as panel.min.js, so nothing could boot. "panel.build.js" is not a
// *.min.js name, so it either serves the real build or 404s. The loader asks
// for this one first and keeps panel.min.js as its fallback.
const buildPath = path.join(root, 'panel.build.js');
const src = fs.readFileSync(srcPath, 'utf8');

// Keep the top /* ... */ license/disclaimer block exactly as written.
const m = src.match(/^\/\*[\s\S]*?\*\//);
const banner = m ? m[0] + '\n' : '';

esbuild.transform(src, {
  minifyWhitespace: true,
  minifyIdentifiers: false,
  minifySyntax: false,
  legalComments: 'none',
  loader: 'js',
}).then((res) => {
  const out = banner + res.code;
  fs.writeFileSync(outPath, out);
  fs.writeFileSync(buildPath, out);
  const pct = ((1 - out.length / src.length) * 100).toFixed(1);
  console.log(`panel.min.js + panel.build.js: ${src.length} -> ${out.length} bytes (-${pct}%)`);
}).catch((e) => { console.error(e); process.exit(1); });
