// Node's own test runner on the plugin's pure core (Node >= 23 runs .ts by stripping types):
//   node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";

import * as core from "../packages/backend/src/core.ts";
import { EP, path } from "../packages/backend/src/endpoints.ts";

const scope = (...hosts: string[]) =>
  JSON.stringify({ target: { scope: { include: hosts.map((h) => ({ enabled: true, protocol: "any", host: "^" + h.replace(/[.-]/g, (c) => "\\" + c) + "$", file: "^/.*" })), exclude: [] } } });

const openapi = JSON.stringify({
  openapi: "3.0.3", info: { title: "AcmeShop" },
  servers: [{ url: "https://api.acme.com" }, { url: "https://staging.acme-internal.net" }],
  paths: {
    "/v1/users/{id}": { get: { parameters: [{ name: "id", in: "path" }, { name: "expand", in: "query" }, { name: "bad name\r\n", in: "query" }] } },
    "/v1/orders": { post: {}, servers: [{ url: "https://api.acme.com" }] },
    "/debug": { get: {}, servers: [{ url: "https://evil.com;touch /tmp/pwn" }, { url: "https://staging.acme-internal.net" }] },
    "/a b\r\nX: 1": { get: {} },
  },
});

test("base URL: https only, http for loopback with the toggle, no userinfo/path/query", () => {
  assert.equal(core.normaliseBase("https://App.Tajapps.com/", false), "https://app.tajapps.com");
  assert.throws(() => core.normaliseBase("http://app.tajapps.com", true));
  assert.throws(() => core.normaliseBase("http://127.0.0.1:8000", false));
  assert.equal(core.normaliseBase("http://127.0.0.1:8000", true), "http://127.0.0.1:8000");
  for (const bad of ["https://u:p@x.com", "https://x.com/api", "https://x.com?a=1", "ftp://x.com", "http://localhost.evil.com"]) {
    assert.throws(() => core.normaliseBase(bad, true), bad);
  }
  assert.throws(() => core.checkToken("abc\r\nX-Evil: 1"));
});

test("this Kali's link: strict parse; a typed token always wins; the page text never holds a token", () => {
  const now = 1_800_000_000;
  const tok = "privara_kl_LINKtoken_0123456789abcdef";
  const doc = (o: Record<string, unknown>) => JSON.stringify({ schema: core.KALI_LINK_SCHEMA, base: "https://app.tajapps.com/", token: tok,
    expires_at: now + 3600, kali_id: 181, kali_name: "kali <b>", ...o });
  const ok = core.parseKaliLink(doc({}), now);
  assert.ok(ok.link && ok.link.base === "https://app.tajapps.com" && ok.link.token === tok && ok.link.kaliName === "kali b");
  for (const bad of [{ schema: "privara.kali-link/2" }, { base: "http://127.0.0.1:18090" }, { base: "https://u:p@x.com" },
    { base: "https://x.com/api" }, { token: "pvt_api_token_0123456789abcdef" }, { token: "privara_kl_a b c d e f g h i j" },
    { expires_at: now - 1 }, { expires_at: "soon" }]) {
    const r = core.parseKaliLink(doc(bad), now);
    assert.ok(!r.link && r.present && r.problem, JSON.stringify(bad));
  }
  assert.ok(!core.parseKaliLink("not json", now).link);
  assert.equal(core.chooseAuth("https://mine.example", "pvt_typed_0123456789", false, ok).source, "manual");
  assert.equal(core.chooseAuth("https://mine.example", "pvt_typed_0123456789", false, ok).token, "pvt_typed_0123456789");
  const viaLink = core.chooseAuth("https://mine.example", "  ", true, ok);
  assert.ok(viaLink.source === "link" && viaLink.token === tok && viaLink.base === "https://app.tajapps.com" && viaLink.local === false);
  assert.equal(core.chooseAuth("https://mine.example", "", false, core.LINK_ABSENT).source, "none");
  assert.equal(core.tokenStateText("link", ok), "Connected automatically through this Kali's Privara link (kali b)");
  assert.equal(core.tokenStateText("manual", ok), "token set by you");
  const denied = { link: null, present: true, problem: core.KALI_LINK_ROOT_ONLY };
  assert.ok(core.tokenStateText("none", denied).includes("root-only; run Caido as root or paste a token"));
  assert.ok(!core.tokenStateText("link", ok).includes(tok));
});

test("scrub removes the token and bearer-shaped values", () => {
  const t = "pvt_SECRET_0123456789";
  const s = core.scrub(`denied for Bearer ${t} token=${t}`, t);
  assert.ok(!s.includes(t) && s.includes("<token>"));
});

test("API map: in scope is exactly burp-scope.json; hostile hosts and paths dropped", () => {
  const m = core.parseApiMap(openapi, scope("api.acme.com"));
  assert.deepEqual(m.inScopeHosts, ["api.acme.com"]);
  assert.equal(m.endpoints.length, 4);
  assert.ok(m.endpoints.every((e) => core.hostClean(e.host) === e.host && !/\s/.test(e.path)));
  assert.ok(m.endpoints.every((e) => e.inScope === (e.host === "api.acme.com")));
  const u = m.endpoints.find((e) => e.host === "api.acme.com" && e.path === "/v1/users/{id}")!;
  assert.ok(core.rawRequest(u).startsWith("GET /v1/users/{id}?expand= HTTP/1.1\r\nHost: api.acme.com\r\n"));
  assert.deepEqual(core.parseApiMap(openapi, scope()).inScopeHosts, []);
  assert.deepEqual(core.parseApiMap(openapi, null).inScopeHosts, []);
  assert.equal(core.fromScopeRegex("^.*$"), null);
  assert.equal(core.fromScopeRegex("^api.acme.com$"), null);
  assert.equal(core.fromScopeRegex("^api\\.acme\\.com$"), "api.acme.com");
});

const status = (verified: boolean) => ({
  selected: 3, limits: { per_minute: 120, burst: 3 },
  harnesses: [{ id: 3, name: "toybank", verified, meta: { hosts: ["api.acme.com", "*.svc.acme.com", "bad host;rm"] } }],
});

test("forging: only an enabled, scope-checked host of a verified harness is signed", () => {
  let now = 1_000_000;
  const g = new core.ForgeGate(() => now);
  g.on = true;
  assert.equal(g.decide("api.acme.com").sign, false);           // no harness
  g.loadStatus(status(true), 0);
  assert.deepEqual(g.patterns, ["api.acme.com", "*.svc.acme.com"]);
  assert.equal(g.decide("api.acme.com").sign, false);           // not enabled
  assert.notEqual(g.enable("evil.example", { scope: "acme", allowed: true }), null);
  assert.notEqual(g.enable("api.acme.com.evil.com", { scope: "acme", allowed: true }), null);
  assert.notEqual(g.enable("api.acme.com", { scope: null, allowed: true }), null);   // no scope on the device
  assert.notEqual(g.enable("x.svc.acme.com", { scope: "acme", allowed: false }), null);
  assert.equal(g.enable("api.acme.com", { scope: "acme", allowed: true }), null);
  assert.ok(g.candidate("api.acme.com"));
  assert.ok(!core.hostAllowed("svc.acme.com", g.patterns));
  assert.equal(g.decide("api.acme.com").sign, true);
  assert.equal(g.decide("api.acme.com").sign, true);
  assert.equal(g.decide("api.acme.com").sign, true);
  assert.equal(g.decide("api.acme.com").sign, false);           // burst 3
  now += 60_000;
  g.onRefusal("api.acme.com", new core.ApiError(400, "signing limit reached (120 per minute, burst 30) -- slow down"));
  assert.equal(g.decide("api.acme.com").sign, false);           // back-off
  now += core.BACKOFF_MS + 1000;
  assert.equal(g.decide("api.acme.com").sign, true);
  g.onRefusal("api.acme.com", new core.ApiError(400, "api.acme.com is outside this device's engagement scope 'acme'"));
  assert.ok(!g.candidate("api.acme.com"));
  g.enable("api.acme.com", { scope: "acme", allowed: true });
  g.onRefusal("api.acme.com", new core.ApiError(401, "invalid token"));
  assert.equal(g.on, false);
  const g2 = new core.ForgeGate(() => now);
  g2.on = true;
  g2.loadStatus(status(false), 0);
  assert.equal(g2.harnessId, 0);
  assert.notEqual(g2.enable("api.acme.com", { scope: "acme", allowed: true }), null);
});

test("sign answers: CR/LF in a header is refused; body base64 round-trips", () => {
  assert.throws(() => core.checkSignAnswer({ ok: true, headers: { "X-Sig": "a\r\nInjected: 1" } }));
  assert.throws(() => core.checkSignAnswer({ ok: false, error: "boom" }));
  const a = core.checkSignAnswer({ ok: true, headers: { "X-Sig": "abc" }, remove: ["X-Old", "bad name"], body_b64: core.b64encode(core.utf8("{\"é\":1}")) });
  assert.deepEqual(a.set, [["X-Sig", "abc"]]);
  assert.deepEqual(a.remove, ["X-Old"]);
  assert.equal(new TextDecoder().decode(a.body!), "{\"é\":1}");
  assert.equal(core.b64encode(Uint8Array.from([0, 1, 2, 253, 254, 255])), Buffer.from([0, 1, 2, 253, 254, 255]).toString("base64"));
});

test("findings: wrong schema refused", () => {
  assert.throws(() => core.parseFindings({ schema: "x", findings: [] }));
  assert.equal(core.parseFindings({ schema: core.FINDINGS_SCHEMA, findings: [{ id: "a", severity: "HIGH" }], app: { name: "A" } }).findings[0]!.severity, "high");
});

test("endpoints fill only integers into the path", () => {
  assert.equal(path(EP.FORGE_SIGN, 7), "/api/instances/7/ipa/forge/sign");
  assert.equal(path(EP.BUNDLE, 7, 41), "/api/instances/7/ipa/runs/41/bundle");
});

test("errors shown in the page: Caido's RPC wrapper and the plugin stack are removed (seen live in Caido 0.59)", () => {
  // the exact shape the real Caido 0.59.0 frontend received, 2026-11-12
  const live = "RPC function 'saveSettings' threw an error: https only: plain http would send your token in clear " +
    "(http is allowed for localhost development only) at normaliseBase (plugin:500:17) at saveSettings (plugin:967:29)";
  assert.equal(core.cleanError(new Error(live)),
    "https only: plain http would send your token in clear (http is allowed for localhost development only)");
  assert.equal(core.cleanError("RPC function 'testConnection' threw an error: HTTP 401: the platform answered with a redirect; " +
    "check the base URL at ApiError (plugin:662:5) at call (plugin:941:15)"), "HTTP 401: the platform answered with a redirect; check the base URL");
  assert.equal(core.cleanError(new Error("plain message")), "plain message");
  assert.equal(core.cleanError(""), "the call failed");
});
