// Privara iOS kit for Caido -- backend plugin (Caido's QuickJS runtime).
// Talks ONLY to the Privara public API, with the
// customer's own token, over HTTPS (http only for loopback with the explicit dev toggle).
//
//  * The token is kept in this plugin's own database (Caido's data folder, this machine) and is
//    NEVER returned to the page: getSettings says only whether one is set.
//  * On a Privara cloud Kali with the link on, and no token typed by hand, this Kali's link token
//    (/etc/privara/kali-link.json, read-only, never stored in the plugin database) is used instead.
//    A typed token always wins; useKaliLink drops it and goes back to the link.
//  * Calls use Caido's `fetch`, not `sdk.requests.send`, so they never enter Caido's HTTP history
//    with the Authorization header in them.
//  * Request forging hooks Caido's upstream-plugin event: Caido calls it only for domains the user
//    enabled for this plugin under Settings > Network > Upstream Plugins, AND this gate signs only an enabled,
//    scope-checked host of a VERIFIED harness. Everything else is returned untouched (undefined).

import type { SDK } from "caido:plugin";
import { Blob, fetch } from "caido:http";
// Read-only use: this Kali's Privara link file (core.KALI_LINK_PATH). Nothing else is read or written.
import { readFile, stat } from "fs/promises";
// The browser build: the node one imports "module" and "worker_threads", which QuickJS lacks.
import { unzipSync, strFromU8 } from "fflate/browser";

import * as core from "./core";
import { EP, method, path } from "./endpoints";

type Obj = Record<string, unknown>;
type Settings = {
  baseUrl: string; allowLocalhostHttp: boolean; hasToken: boolean; deviceId: number; version: string;
  tokenSource: "manual" | "link" | "none"; tokenState: string;
};
type Event = { at: number; method: string; host: string; path: string; result: string; detail: string };

const state = { base: core.DEFAULT_BASE, token: "", local: false, device: 0 };
const gate = new core.ForgeGate();
const counters = { signed: 0, failed: 0, passed: 0 };
const events: Event[] = [];
let lastError = "";

// ------------------------------------------------------------------ settings (plugin database)

async function db(sdk: SDK) {
  const d = await sdk.meta.db();
  await d.exec("CREATE TABLE IF NOT EXISTS privara_settings (k TEXT PRIMARY KEY, v TEXT NOT NULL)");
  return d;
}

async function loadSettings(sdk: SDK): Promise<void> {
  const d = await db(sdk);
  const rows = await (await d.prepare("SELECT k, v FROM privara_settings")).all<{ k: string; v: string }>();
  for (const r of rows) {
    if (r.k === "base") state.base = r.v;
    if (r.k === "token") state.token = r.v;
    if (r.k === "local") state.local = r.v === "1";
    if (r.k === "device") state.device = Number(r.v) || 0;
  }
}

async function put(sdk: SDK, k: string, v: string): Promise<void> {
  const d = await db(sdk);
  await (await d.prepare("INSERT INTO privara_settings (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v")).run(k, v);
}

// ------------------------------------------------------------------ this Kali's Privara link

let linkCache: { mtime: number; size: number; result: core.KaliLinkResult; loaded: boolean } =
  { mtime: -1, size: -1, result: core.LINK_ABSENT, loaded: false };

function linkPath(): string {
  // PRIVARA_KALI_LINK_FILE: tests only (the smoke run points it at a temp file).
  try {
    const p = (globalThis as unknown as { process?: { env?: Record<string, string | undefined> } }).process?.env?.PRIVARA_KALI_LINK_FILE;
    return p ? p : core.KALI_LINK_PATH;
  } catch {
    return core.KALI_LINK_PATH;
  }
}

/** The link file, re-read only when it changed (mtime/size), the cached link expired, or forced. */
async function kaliLink(force = false): Promise<core.KaliLinkResult> {
  const now = Math.floor(Date.now() / 1000);
  const p = linkPath();
  let mtime = -1;
  let size = -1;
  let code = "";
  try {
    const s = await stat(p);
    mtime = Number(s.mtimeMs) || 0;
    size = Number(s.size) || 0;
  } catch (e) {
    code = String((e as { code?: string }).code ?? (e as Error).message ?? "");
  }
  const expired = !!linkCache.result.link && linkCache.result.link.expiresAt <= now;
  if (!force && linkCache.loaded && mtime === linkCache.mtime && size === linkCache.size && !expired) return linkCache.result;
  let result: core.KaliLinkResult;
  if (mtime < 0) {
    result = /EACCES|EPERM|denied|permission/i.test(code) ? { link: null, present: true, problem: core.KALI_LINK_ROOT_ONLY } : core.LINK_ABSENT;
  } else if (size > 16 * 1024) {
    result = { link: null, present: true, problem: "this Kali's link file is too large" };
  } else {
    try {
      result = core.parseKaliLink(await readFile(p, "utf8") as string, now);
    } catch (e) {
      const c = String((e as { code?: string }).code ?? (e as Error).message ?? "");
      result = /ENOENT/.test(c) ? core.LINK_ABSENT : { link: null, present: true, problem: core.KALI_LINK_ROOT_ONLY };
    }
  }
  linkCache = { mtime, size, result, loaded: true };
  return result;
}

async function auth(): Promise<core.Auth> {
  return core.chooseAuth(state.base, state.token, state.local, await kaliLink());
}

/** Every token that may appear in text (the typed one and the link's), for scrubbing. */
function scrubAll(text: string): string {
  return core.scrub(core.scrub(text, state.token), linkCache.result.link?.token ?? "");
}

async function settings(): Promise<Settings> {
  const a = await auth();
  return {
    baseUrl: state.base, allowLocalhostHttp: state.local, hasToken: a.source !== "none", deviceId: state.device,
    version: core.VERSION, tokenSource: a.source, tokenState: core.tokenStateText(a.source, linkCache.result),
  };
}

function log(sdk: SDK, msg: string): void {
  sdk.console.log("[privara] " + scrubAll(msg).slice(0, 2000));
}

// ------------------------------------------------------------------ the Privara API

async function callOnce(a: core.Auth, ep: string, iid: number, rid: number, query: string, body?: Obj): Promise<Response> {
  const base = core.normaliseBase(a.base, a.local);
  if (!a.token) {
    throw new core.ApiError(0, "set your Privara API token in the Privara page first (on a Privara Kali with the link on, this Kali's link is used instead)");
  }
  const url = base + path(ep, iid, rid) + query;
  const res = await fetch(url, {
    method: method(ep),
    headers: { Authorization: "Bearer " + a.token, Accept: "application/json", "User-Agent": `privara-caido/${core.VERSION}`,
      ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? new Blob([JSON.stringify(body)]) : undefined,
  });
  // Caido's fetch has no "do not follow" switch. A redirect is reported, never used: the Privara API
  // does not redirect /api routes, so one means the base URL is wrong.
  if (res.redirected || (res.url && !res.url.startsWith(base + "/"))) {
    throw new core.ApiError(res.status, "the platform answered with a redirect; check the base URL");
  }
  if (res.status !== 200 && res.status !== 201) {
    throw new core.ApiError(res.status, scrubAll(core.detailOf(await res.text())).slice(0, 600));
  }
  return res;
}

async function call(ep: string, iid = 0, rid = 0, query = "", body?: Obj): Promise<Response> {
  const a = await auth();
  try {
    return await callOnce(a, ep, iid, rid, query, body);
  } catch (e) {
    // A 401 on the link: re-read the file ONCE (the platform rotates it daily) and retry if it changed.
    if (e instanceof core.ApiError && e.status === 401 && a.source === "link") {
      const fresh = await kaliLink(true);
      if (fresh.link && fresh.link.token !== a.token) return await callOnce(await auth(), ep, iid, rid, query, body);
    }
    throw e;
  }
}

type Response = Awaited<ReturnType<typeof fetch>>;

async function json(ep: string, iid = 0, rid = 0, query = "", body?: Obj): Promise<unknown> {
  const res = await call(ep, iid, rid, query, body);
  try {
    return JSON.parse(await res.text());
  } catch {
    throw new core.ApiError(0, "the platform did not answer with JSON");
  }
}

function need(): number {
  if (!state.device) throw new core.ApiError(0, "choose an iOS Analysis device first");
  return state.device;
}

function record(m: string, host: string, p: string, result: string, detail: string): void {
  events.unshift({ at: Date.now(), method: m, host, path: p, result, detail: scrubAll(detail).slice(0, 300) });
  events.length = Math.min(events.length, 200);
}

// ------------------------------------------------------------------ the API the page calls

const api = {
  getSettings: async (_sdk: SDK): Promise<Settings> => settings(),

  saveSettings: async (sdk: SDK, base: string, token: string, local: boolean): Promise<Settings> => {
    const b = core.normaliseBase(base, local);
    const t = token ? core.checkToken(token) : state.token;
    state.base = b;
    state.local = local;
    state.token = t;
    await put(sdk, "base", b);
    await put(sdk, "local", local ? "1" : "0");
    await put(sdk, "token", t);
    return settings();
  },

  forgetToken: async (sdk: SDK): Promise<Settings> => {
    state.token = "";
    gate.on = false;
    await put(sdk, "token", "");
    return settings();
  },

  /** Drop the token typed by hand and go back to this Kali's Privara link (re-read now). */
  useKaliLink: async (sdk: SDK): Promise<Settings> => {
    state.token = "";
    gate.on = false;
    await put(sdk, "token", "");
    await kaliLink(true);
    return settings();
  },

  testConnection: async (_sdk: SDK): Promise<string> => String((await json(EP.WHOAMI) as Obj).username ?? ""),

  devices: async (_sdk: SDK): Promise<Array<{ id: number; name: string; status: string; scope: string }>> =>
    (await json(EP.DEVICES) as Obj[]).filter(core.isAnalysisDevice).map((d) => ({
      id: Number(d.id), name: String(d.name ?? ""), status: String(d.status ?? ""), scope: String(d.scope ?? ""),
    })),

  setDevice: async (sdk: SDK, iid: number): Promise<Settings> => {
    // Only a real device id: an empty device list in the page sends 0 (or NaN), which must neither
    // forget the saved device nor switch forging off.
    if (!Number.isInteger(iid) || iid <= 0) throw new core.ApiError(0, "choose an iOS Analysis device first");
    if (iid !== state.device) gate.reset("a different device was chosen: load its forge status");
    state.device = iid;
    await put(sdk, "device", String(state.device));
    return settings();
  },

  runOp: async (_sdk: SDK, op: string, guestPath: string): Promise<Obj> => {
    if (!core.RUN_OPS.includes(op)) throw new core.ApiError(0, "only apimap, cloudcheck and deeplinks can be run from here");
    return await json(EP.SCAN, need(), 0, "", { op, path: guestPath }) as Obj;
  },

  runs: async (_sdk: SDK): Promise<Obj[]> =>
    ((await json(EP.RUNS, need(), 0, "?limit=100") as Obj).runs as Obj[] ?? []).filter((r) => r.ok),

  importMap: async (_sdk: SDK, rid: number): Promise<core.ApiMap & { raws: string[] }> => {
    const res = await call(EP.BUNDLE, need(), rid);
    const zip = new Uint8Array(await res.arrayBuffer());
    const files = unzipSync(zip, {
      filter: (f) => /(^|\/)(openapi|burp-scope)\.json$/.test(f.name) && f.originalSize < 16 * 1024 * 1024,
    });
    let openapi: string | null = null;
    let scope: string | null = null;
    for (const [name, data] of Object.entries(files)) {
      if (name.endsWith("/openapi.json") || name === "openapi.json") openapi = strFromU8(data);
      if (name.endsWith("/burp-scope.json") || name === "burp-scope.json") scope = strFromU8(data);
    }
    const map = core.parseApiMap(openapi, scope);
    return { ...map, raws: map.endpoints.map(core.rawRequest) };
  },

  findings: async (_sdk: SDK, rid: number) =>
    core.parseFindings(await json(EP.REPORT, need(), 0, `?run_id=${Math.trunc(rid)}&format=json`) as Obj),

  forgeLoad: async (_sdk: SDK, harnessId: number) => {
    gate.loadStatus(await json(EP.FORGE_STATUS, need()) as Obj, Math.trunc(harnessId || 0));
    return forgeState();
  },

  forgeEnable: async (_sdk: SDK, host: string) => {
    const h = core.hostClean(host);
    // A host outside the harness's HOSTS is never even sent to the platform's scope check.
    if (!h || !core.hostAllowed(h, gate.patterns)) return { ...forgeState(), message: `${host} is not one of the harness's HOSTS` };
    const why = gate.enable(h, await json(EP.SCOPE_CHECK, need(), 0, "?target=" + encodeURIComponent(h)) as Obj);
    return { ...forgeState(), message: why === null ? `${h} enabled for signing` : `${h} NOT enabled: ${why}` };
  },

  forgeDisable: async (_sdk: SDK, host: string) => {
    gate.disable(host, "disabled by you");
    return forgeState();
  },

  forgeSwitch: async (sdk: SDK, on: boolean) => {
    gate.on = !!on;
    log(sdk, "request forging " + (gate.on ? "ON" : "OFF"));
    return forgeState();
  },

  forgeState: async (_sdk: SDK) => forgeState(),
};

function forgeState() {
  return {
    on: gate.on, harness: gate.harnessNote, patterns: gate.patterns, hosts: [...gate.hosts.values()],
    counters: { ...counters }, lastError: scrubAll(lastError), events: events.slice(0, 50),
    message: "",
  };
}

export type API = {
  [K in keyof typeof api]: (typeof api)[K] extends (sdk: SDK, ...a: infer A) => infer R ? (...a: A) => R : never;
};

// ------------------------------------------------------------------ init

export async function init(sdk: SDK<API>): Promise<void> {
  await loadSettings(sdk as unknown as SDK);
  for (const [name, fn] of Object.entries(api)) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    sdk.api.register(name as keyof API, fn as any);
  }

  sdk.events.onUpstream(async (_s, raw) => {
    const host = raw.getHost();
    if (!gate.candidate(host)) return undefined;           // not ours: untouched, never sent anywhere
    const spec = raw.toSpec();
    const p = spec.getPath();
    const d = gate.decide(host);
    if (!d.sign) {
      counters.passed++;
      return undefined;
    }
    const headers: Array<[string, string]> = [];
    for (const [k, vs] of Object.entries(spec.getHeaders())) for (const v of vs) headers.push([k, v]);
    const body = spec.getBody()?.toRaw() ?? new Uint8Array(0);
    const request = { method: spec.getMethod(), url: spec.getUrl(), headers, body_b64: core.b64encode(body) };
    let ans: core.SignAnswer;
    try {
      ans = core.checkSignAnswer(await json(EP.FORGE_SIGN, state.device, 0, "", { harness_id: gate.harnessId, request }) as Obj);
    } catch (e) {
      const why = e instanceof core.ApiError ? gate.onRefusal(host, e) : String((e as Error).message ?? e);
      counters.failed++;
      lastError = why;
      record(request.method, host, p, "failed", why);
      log(sdk as unknown as SDK, `not signed: ${request.method} ${host}${p} :: ${why}`);
      return undefined;                                    // goes out unsigned
    }
    for (const n of ans.remove) spec.removeHeader(n);
    for (const [k, v] of ans.set) spec.setHeader(k, v);
    if (ans.body) spec.setBody(ans.body, { updateContentLength: true });
    counters.signed++;
    record(request.method, host, p, "signed", `${ans.set.length} header(s)`);
    return spec;
  });

  log(sdk as unknown as SDK, `Privara iOS kit ${core.VERSION} loaded; request forging is OFF until switched on`);
  if ((await auth()).source === "link") {
    log(sdk as unknown as SDK, "connected through this Kali's Privara link; a token typed in the Privara page overrides it");
  }
}
