// Checks that every locale translates exactly the strings the UI uses.
// Run: npm run check-i18n
//
// Strings come from literals passed to t(), and from tables marked with an
// "// i18n-table" comment whose values are translated through t() later.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const src = fileURLToPath(new URL("../src/", import.meta.url));
const localeDir = join(src, "locales");
const STRING = String.raw`"(?:[^"\\]|\\.)*"`;

// Locale files are object literals of "english": "translation" pairs.
function keys(file) {
  const text = readFileSync(join(localeDir, file), "utf8");
  const out = new Set();
  for (const m of text.matchAll(new RegExp(String.raw`^\s*(${STRING})\s*:`, "gm"))) out.add(JSON.parse(m[1]));
  return out;
}

function walk(dir, files = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== "locales") walk(p, files);
    } else if (/\.tsx?$/.test(name)) files.push(p);
  }
  return files;
}

const used = new Set();
for (const f of walk(src)) {
  const text = readFileSync(f, "utf8");
  for (const m of text.matchAll(new RegExp(String.raw`\bt\(\s*(${STRING})`, "g"))) used.add(JSON.parse(m[1]));
  // Table keys are bare identifiers or numbers, so every string literal in
  // a table is a value to translate.
  for (const block of text.matchAll(/\/\/ i18n-table\n([\s\S]*?)\n[}\]];/g)) {
    for (const m of block[1].matchAll(new RegExp(STRING, "g"))) used.add(JSON.parse(m[0]));
  }
}

const locales = readdirSync(localeDir).filter((f) => f.endsWith(".ts"));
let failed = false;
for (const file of locales) {
  const set = keys(file);
  for (const k of used) {
    if (!set.has(k)) {
      console.error(`${file}: missing translation: ${JSON.stringify(k)}`);
      failed = true;
    }
  }
  for (const k of set) {
    if (!used.has(k)) console.warn(`${file}: unused: ${JSON.stringify(k)}`);
  }
}
console.log(`${used.size} UI strings; locales: ${locales.join(", ")}`);
process.exit(failed ? 1 : 0);
