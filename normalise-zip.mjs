// Rewrite dist/plugin_package.zip so its bytes depend only on its contents: entries in a fixed
// order, one fixed timestamp, one compression level. caido-dev stamps the build time into every
// entry, so without this two builds of the same sources differ. Run by build.sh after caido-dev.
//   node normalise-zip.mjs [dist/plugin_package.zip]
import fs from "node:fs";
import { unzipSync, zipSync } from "fflate";

const path = process.argv[2] || "dist/plugin_package.zip";
// Zip stores LOCAL date/time fields and fflate fills them from the Date's local fields, so build the
// Date from local fields: every machine, whatever its time zone, writes 2026-11-12 00:00:00.
const MTIME = new Date(2026, 10, 12, 0, 0, 0);
const files = unzipSync(new Uint8Array(fs.readFileSync(path)));
const names = Object.keys(files).sort();
const out = {};
for (const n of names) out[n] = [files[n], { mtime: MTIME, level: 9 }];
fs.writeFileSync(path, zipSync(out, { mtime: MTIME, level: 9 }));
console.log(`normalised ${path}: ${names.length} entries`);
