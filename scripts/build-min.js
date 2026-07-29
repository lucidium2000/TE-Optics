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
  const pct = ((1 - out.length / src.length) * 100).toFixed(1);
  console.log(`panel.min.js: ${src.length} -> ${out.length} bytes (-${pct}%)`);
}).catch((e) => { console.error(e); process.exit(1); });
