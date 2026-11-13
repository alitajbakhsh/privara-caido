// Runs the BUILT backend (packages/backend/dist/index.js) in Node with a fake Caido: `caido:http`
// is mapped to Node's own fetch/Blob, and the SDK is a recording stub. Not Caido's QuickJS runtime,
// but it drives the real bundle end to end against a loopback stub of the Privara API:
//   node test/backend.smoke.mjs [bundle.zip]
// With a bundle path (the platform's contract test passes its REAL bundle) that one is served.
import { registerHooks } from "node:module";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { zipSync, strToU8 } from "fflate";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const shim = "data:text/javascript," + encodeURIComponent(
  "export const fetch = globalThis.fetch; export const Blob = globalThis.Blob; export const Headers = globalThis.Headers;");
registerHooks({
  resolve(spec, ctx, next) {
    if (spec === "caido:http") return { url: shim, shortCircuit: true };
    return next(spec, ctx);
  },
});

const TOKEN = "pvt_smoke_SECRET_0123456789abcdef";
let fails = 0, passes = 0;
const check = (name, ok, got) => {
  if (ok) { passes++; console.log("  PASS  " + name); } else { fails++; console.log("  FAIL  " + name + "   -> " + JSON.stringify(got)); }
};

const bundleArg = process.argv[2];
const bundle = bundleArg ? fs.readFileSync(bundleArg) : Buffer.from(zipSync({
  "AcmeShop-1/openapi.json": strToU8(JSON.stringify({ openapi: "3.0.3", info: { title: "AcmeShop" },
    servers: [{ url: "https://api.acme.com" }, { url: "https://staging.acme-internal.net" }],
    paths: { "/v1/users/{id}": { get: { parameters: [{ name: "expand", in: "query" }] } } } })),
  "AcmeShop-1/burp-scope.json": strToU8(JSON.stringify({ target: { scope: { include: [
    { enabled: true, protocol: "any", host: "^api\\.acme\\.com$", file: "^/.*" }] } } })),
}));

const signs = [];
const authSeen = [];
let altToken = "";   // a second token the stub accepts (this Kali's link, S16-S21)
let onStale = null;  // { token, fn }: run fn (the platform rotating the link file) when that token arrives
let refuseNext = "";
const handler = (req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    const send = (st, obj, ct = "application/json") => {
      const b = Buffer.isBuffer(obj) ? obj : Buffer.from(JSON.stringify(obj));
      res.writeHead(st, { "Content-Type": ct, "Content-Length": b.length });
      res.end(b);
    };
    authSeen.push(String(req.headers.authorization));
    if (onStale && req.headers.authorization === "Bearer " + onStale.token) { const f = onStale.fn; onStale = null; f(); }
    if (req.headers.authorization !== "Bearer " + TOKEN && !(altToken && req.headers.authorization === "Bearer " + altToken)) {
      return send(401, { detail: "invalid token" });
    }
    const u = new URL(req.url, "http://x");
    if (u.pathname === "/api/whoami") return send(200, { username: "demo" });
    if (u.pathname === "/api/instances") return send(200, [
      { id: 7, name: "ios-lab", status: "running", scope: "acme", capabilities: ["ipa_analysis"] },
      { id: 8, name: "kali", status: "running", capabilities: ["shell"] }]);
    if (u.pathname === "/api/instances/7/ipa/runs/41/bundle") return send(200, bundle, "application/zip");
    if (u.pathname === "/api/instances/7/ipa/forge") return send(200, { selected: 3, limits: { per_minute: 120, burst: 30 },
      harnesses: [{ id: 3, name: "toybank", verified: true, meta: { hosts: ["api.acme.com"] } }] });
    if (u.pathname === "/api/instances/7/scope") return send(200, { scope: "acme", allowed: u.searchParams.get("target") === "api.acme.com" });
    if (u.pathname === "/api/instances/7/ipa/forge/sign") {
      signs.push(JSON.parse(body));
      if (refuseNext) { const d = refuseNext; refuseNext = ""; return send(400, { detail: d }); }
      return send(200, { ok: true, harness: "toybank", headers: { "X-Sig": "c2ln" }, remove: ["X-Old"],
        body_b64: Buffer.from("{\"signed\":true}").toString("base64") });
    }
    send(404, { detail: "Not Found" });
  });
};
const srv = http.createServer(handler);
await new Promise((r) => srv.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${srv.address().port}`;

// ---------------------------------------------------------------- a recording fake of Caido's SDK
const rows = new Map();
const logs = [];
const api = {};
let upstream = null;
const sdk = {
  console: { log: (m) => logs.push(String(m)) },
  meta: {
    db: async () => ({
      exec: async () => undefined,
      prepare: async (sql) => ({
        all: async () => [...rows].map(([k, v]) => ({ k, v })),
        run: async (k, v) => { if (sql.startsWith("INSERT")) rows.set(k, v); return { changes: 1, lastInsertRowid: 0 }; },
        get: async () => undefined,
      }),
    }),
  },
  api: { register: (n, fn) => (api[n] = (...a) => fn(sdk, ...a)), send: () => undefined },
  events: { onUpstream: (cb) => (upstream = cb) },
};

function rawReq(host, recorder) {
  const headers = { Host: [host], "X-Old": ["stale"], Cookie: ["session=SESSIONSECRET42"] };
  const spec = {
    getHost: () => host, getPath: () => "/v1/orders", getMethod: () => "POST", getUrl: () => `https://${host}/v1/orders?x=1`,
    getHeaders: () => headers, getBody: () => ({ toRaw: () => new TextEncoder().encode("{\"a\":1}") }),
    removeHeader: (n) => recorder.push(["remove", n]), setHeader: (k, v) => recorder.push(["set", k, v]),
    setBody: (b, o) => recorder.push(["body", Buffer.from(b).toString(), o]),
  };
  return { getHost: () => host, toSpec: () => spec };
}

const mod = await import(pathToFileURL(path.join(HERE, "..", "packages", "backend", "dist", "index.js")).href);
await mod.init(sdk);
console.log("\n=== S · the built Caido backend, in a recording fake of Caido ===");
check("S1 init registers the API and hooks the upstream event", typeof api.saveSettings === "function" && typeof upstream === "function",
  Object.keys(api));
let refused = false;
try { await api.saveSettings("http://example.com", TOKEN, true); } catch { refused = true; }
check("S2 a plain-http base URL to a real host is refused", refused);
const s = await api.saveSettings(base, TOKEN, true);
check("S3 settings saved; the page is told only THAT a token is set", s.hasToken === true && !JSON.stringify(s).includes(TOKEN), s);
check("S4 the token is sent as a bearer header (whoami answers)", (await api.testConnection()) === "demo");
const devs = await api.devices();
check("S5 only devices with the ipa_analysis capability are offered", devs.length === 1 && devs[0].id === 7, devs);
let zeroRefused = false;
try { await api.setDevice(0); } catch { zeroRefused = true; }
let nanRefused = false;
try { await api.setDevice(Number("")); } catch { nanRefused = true; }
await api.setDevice(7);
await api.forgeLoad(0);
await api.forgeEnable("api.acme.com");
await api.forgeSwitch(true);
let zeroAgain = false;
try { await api.setDevice(0); } catch { zeroAgain = true; }
const kept = await api.forgeState();
check("S15 setDevice(0 / NaN) is refused (an empty device list in the page) and keeps the device and forging state",
  zeroRefused && nanRefused && zeroAgain && (await api.getSettings()).deviceId === 7 && kept.on === true
  && kept.hosts.some((h) => h.host === "api.acme.com" && h.enabled), { zeroRefused, nanRefused, on: kept.on });
await api.forgeSwitch(false);
await api.setDevice(8);
await api.setDevice(7);
const map = await api.importMap(41);
check("S6 the bundle is unzipped in the backend; in scope is exactly burp-scope.json",
  JSON.stringify(map.inScopeHosts) === JSON.stringify(bundleArg ? map.inScopeHosts : ["api.acme.com"]) &&
  map.endpoints.length > 0 && map.endpoints.every((e) => e.inScope === map.inScopeHosts.includes(e.host)) &&
  map.raws.every((r, i) => r.includes(`\r\nHost: ${map.endpoints[i].host}\r\n`)), { in: map.inScopeHosts, n: map.endpoints.length });
console.log("SMOKE_MAP " + JSON.stringify({ inScopeHosts: map.inScopeHosts, hosts: [...new Set(map.endpoints.map((e) => e.host))].sort() }));

let rec = [];
check("S7 forging OFF: the upstream hook leaves the request alone", (await upstream(sdk, rawReq("api.acme.com", rec))) === undefined
  && signs.length === 0 && rec.length === 0);
await api.forgeLoad(0);
let st = await api.forgeEnable("evil.example");
check("S8 a host outside the harness HOSTS is not even sent to the scope check", /not one of the harness/.test(st.message), st.message);
st = await api.forgeEnable("api.acme.com");
check("S9 a harness host enabled after the platform's scope check", /enabled for signing/.test(st.message), st.message);
await api.forgeSwitch(true);
rec = [];
const out = await upstream(sdk, rawReq("other.example", rec));
check("S10 a request to a host that is not enabled: untouched, and the sign API never hears of it",
  out === undefined && signs.length === 0 && rec.length === 0);
rec = [];
const signed = await upstream(sdk, rawReq("api.acme.com", rec));
const sent = signs[0] || {};
check("S11 an enabled host: the sign call carries harness id, method, URL, headers, body as base64",
  sent.harness_id === 3 && sent.request?.method === "POST" && sent.request?.url === "https://api.acme.com/v1/orders?x=1" &&
  Buffer.from(sent.request?.body_b64 || "", "base64").toString() === "{\"a\":1}", sent);
check("S12 ...and the request is rewritten: header removed, signed header set, body replaced",
  signed !== undefined && JSON.stringify(rec) === JSON.stringify([["remove", "X-Old"], ["set", "X-Sig", "c2ln"],
    ["body", "{\"signed\":true}", { updateContentLength: true }]]), rec);
refuseNext = "api.acme.com is outside this device's engagement scope 'acme'";
rec = [];
const r1 = await upstream(sdk, rawReq("api.acme.com", rec));
const r2 = await upstream(sdk, rawReq("api.acme.com", rec));
check("S13 a scope refusal from the platform disables the host; it is not tried again",
  r1 === undefined && r2 === undefined && signs.length === 2 && rec.length === 0, signs.length);
const leaked = logs.concat(JSON.stringify(await api.forgeState())).some((l) => l.includes(TOKEN) || l.includes("SESSIONSECRET42"));
check("S14 no log line or state shown to the page holds the token or a request header value", !leaked && logs.length > 0, logs);

// ---------------------------------------------------------------- this Kali's Privara link
// The link must name an https base, so an https loopback twin of the stub serves S19-S20 (a cert
// made here by openssl; certificate checks are off for THIS test process only).
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pv-kl-"));
const linkFile = path.join(tmp, "kali-link.json");
process.env.PRIVARA_KALI_LINK_FILE = linkFile;
const now = Math.floor(Date.now() / 1000);
const linkDoc = (b, t, exp = now + 86400) => JSON.stringify({ schema: "privara.kali-link/1", base: b, token: t, expires_at: exp,
  kali_id: 181, kali_name: "kali", note: "x" });
const STALE = "privara_kl_STALEsmoke_0123456789abcd";
const FRESH = "privara_kl_FRESHsmoke_0123456789abcd";
execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1", "-days", "1",
  "-keyout", path.join(tmp, "k.pem"), "-out", path.join(tmp, "c.pem")], { stdio: "ignore" });
const tlsSrv = https.createServer({ key: fs.readFileSync(path.join(tmp, "k.pem")), cert: fs.readFileSync(path.join(tmp, "c.pem")) }, handler);
await new Promise((r) => tlsSrv.listen(0, "127.0.0.1", r));
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const tbase = `https://127.0.0.1:${tlsSrv.address().port}`;

fs.writeFileSync(linkFile, linkDoc(tbase, STALE), { mode: 0o600 });
await api.forgetToken();
let ls = await api.getSettings();
check("S16 no typed token + a valid link file: the page is told the link is in use (never the token)",
  ls.tokenSource === "link" && ls.hasToken && ls.tokenState === "Connected automatically through this Kali's Privara link (kali)"
  && !JSON.stringify(ls).includes(STALE), ls);
await api.saveSettings(base, TOKEN, true);
ls = await api.getSettings();
check("S17 a token typed by hand wins over the link", ls.tokenSource === "manual" && ls.tokenState === "token set by you"
  && (await api.testConnection()) === "demo", ls);
ls = await api.useKaliLink();
check("S18 'Use this Kali's link' drops the typed token (also from the plugin database) and goes back to the link",
  ls.tokenSource === "link" && rows.get("token") === "" && ![...rows.values()].some((v) => String(v).includes(STALE)), ls);
altToken = FRESH;
authSeen.length = 0;
// The platform rotates the file while the stale token is on its way: the stub rewrites it, then answers 401.
onStale = { token: STALE, fn: () => fs.writeFileSync(linkFile, linkDoc(tbase, FRESH) + " ", { mode: 0o600 }) };
let who = "";
try { who = await api.testConnection(); } catch (e) { who = String(e.message); }
check("S19 a 401 on the link token: the file is re-read ONCE and the call retried with the new token",
  who === "demo" && authSeen.length === 2 && authSeen[0] === "Bearer " + STALE && authSeen[1] === "Bearer " + FRESH, { who, authSeen });
altToken = "";
authSeen.length = 0;
let r401 = "";
try { await api.testConnection(); } catch (e) { r401 = String(e.message); }
check("S20 a 401 with no newer token is not retried, and the error holds no token",
  /401/.test(r401) && authSeen.length === 1 && !r401.includes(FRESH), { r401, authSeen });
// The platform writes a NEW file (atomic rename) that this user cannot read (root-only, Caido not root).
fs.rmSync(linkFile);
fs.writeFileSync(linkFile, linkDoc(tbase, FRESH), { mode: 0o000 });
ls = await api.getSettings();
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
check("S21 an unreadable (root-only) link file: the page says so; nothing crashes",
  isRoot || (ls.tokenSource === "none" && ls.tokenState.includes("root-only; run Caido as root or paste a token")), ls);
fs.chmodSync(linkFile, 0o600);
fs.rmSync(linkFile);
ls = await api.getSettings();
const leaked2 = logs.concat(JSON.stringify(await api.forgeState())).some((l) => l.includes(STALE) || l.includes(FRESH));
check("S22 no file: 'no token set'; no log line or page state ever held a link token",
  ls.tokenSource === "none" && ls.tokenState === "no token set" && !leaked2, ls);
tlsSrv.close();
fs.rmSync(tmp, { recursive: true, force: true });

srv.close();
console.log(`\n${passes} passed, ${fails} failed`);
process.exit(fails ? 1 : 0);
