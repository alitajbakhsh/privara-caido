// Privara iOS kit for Caido -- the pure core (no Caido imports), so Node's test runner can drive it.
//
// The same rules as the Privara Burp extension (its core package) and the
// platform itself, one for one:
//   * normaliseBase   = PrivaraConfig.normalise   (https only; http for loopback with the toggle)
//   * hostClean       = ios_kit_kali._clean_host  (hosts come from an UNTRUSTED app)
//   * hostAllowed     = ios_kit_forge.host_allowed ("*.x" is a subdomain of x, never x itself)
//   * parseApiMap     = what the bundle's openapi.json + burp-scope.json say; in scope ONLY what
//                       burp-scope.json lists (the server's scope check), never the client's guess
//   * ForgeGate       = only a VERIFIED harness, an enabled host that passed the server's scope
//                       dry run (with a scope present), the server's own rate numbers, back-off.

export const VERSION = "2026.11.13";
export const DEFAULT_BASE = "https://app.tajapps.com";
export const STATIC_NOTE =
  "Static analysis of the iOS app bundle by Privara, not runtime proof: confirm it against the live backend before reporting it.";

const HOST_RE = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*$/;
const PARAM_RE = /^[A-Za-z0-9_.\-[\]]{1,64}$/;
const PATH_RE = /^\/[\x21-\x7e]{0,2000}$/;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$/;
export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
export const RUN_OPS = ["apimap", "cloudcheck", "deeplinks"];

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string => (v === null || v === undefined ? "" : String(v));

// ------------------------------------------------------------------ config

export function isLoopback(host: string): boolean {
  const h = host.toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "[::1]" || h === "::1";
}

/** scheme://host[:port], or throws an Error whose message a tester can act on. */
export function normaliseBase(raw: string, allowLocalhostHttp: boolean): string {
  let s = (raw || "").trim();
  while (s.endsWith("/")) s = s.slice(0, -1);
  if (!s) throw new Error(`set the Privara base URL (for example ${DEFAULT_BASE})`);
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)(.*)$/.exec(s);
  if (!m) throw new Error("the base URL is not a URL");
  const scheme = m[1]!.toLowerCase();
  const authority = m[2]!;
  const rest = m[3]!;
  if (authority.includes("@")) throw new Error("the base URL must not carry a user name or password");
  if (rest && rest !== "/") {
    if (rest.startsWith("?") || rest.startsWith("#")) throw new Error("the base URL must not have a query or fragment");
    throw new Error(`the base URL is just the site, e.g. ${DEFAULT_BASE} -- no path`);
  }
  const hm = /^(\[[0-9a-fA-F:]+\]|[^:]+)(?::(\d{1,5}))?$/.exec(authority);
  if (!hm) throw new Error("the base URL has no usable host");
  const host = hm[1]!.toLowerCase();
  const port = hm[2] ? Number(hm[2]) : 0;
  if (!host.startsWith("[") && !HOST_RE.test(host)) throw new Error("the base URL has no usable host");
  if (scheme === "http") {
    if (!isLoopback(host)) {
      throw new Error("https only: plain http would send your token in clear (http is allowed for localhost development only)");
    }
    if (!allowLocalhostHttp) throw new Error(`http://${host} needs the 'localhost development' toggle; real platforms are https`);
  } else if (scheme !== "https") {
    throw new Error("the base URL must start with https://");
  }
  return `${scheme}://${host}${port ? ":" + port : ""}`;
}

export function checkToken(token: string): string {
  const t = (token || "").trim();
  if (/[\s]/.test(t)) throw new Error("the token contains spaces or line breaks -- paste it again");
  return t;
}

// ------------------------------------------------------------------ this Kali's Privara link
// On a Privara cloud Kali the platform keeps a short-lived, route-limited token in
// /etc/privara/kali-link.json (root-only, rewritten atomically, rotated daily, deleted when the
// customer turns the link off). With no token typed by hand, the plugin uses it. A typed token wins.

export const KALI_LINK_PATH = "/etc/privara/kali-link.json";
export const KALI_LINK_SCHEMA = "privara.kali-link/1";
export const KALI_LINK_ROOT_ONLY = "this Kali's link file is root-only; run Caido as root or paste a token";
const KALI_TOKEN_RE = /^privara_kl_[A-Za-z0-9_-]{16,200}$/;

export type KaliLink = { base: string; token: string; expiresAt: number; kaliId: number; kaliName: string };
/** present=false: no file (not a Privara Kali, or the link is off), and then problem is "". */
export type KaliLinkResult = { link: KaliLink | null; present: boolean; problem: string };

export const LINK_ABSENT: KaliLinkResult = { link: null, present: false, problem: "" };

export function parseKaliLink(text: string, nowSec: number): KaliLinkResult {
  const bad = (problem: string): KaliLinkResult => ({ link: null, present: true, problem });
  let o: Obj;
  try {
    o = obj(JSON.parse(text));
  } catch {
    return bad("this Kali's link file is not valid JSON");
  }
  if (o.schema !== KALI_LINK_SCHEMA) return bad("this Kali's link file has an unknown schema");
  let base: string;
  try {
    base = normaliseBase(str(o.base), false);
  } catch (e) {
    return bad("this Kali's link file has a bad base URL: " + (e as Error).message);
  }
  if (!base.startsWith("https://")) return bad("this Kali's link file must name an https base URL");
  const token = str(o.token);
  if (!KALI_TOKEN_RE.test(token)) return bad("this Kali's link file does not hold a Kali link token");
  if (typeof o.expires_at !== "number") return bad("this Kali's link file has no expiry");
  if (o.expires_at <= nowSec) return bad("this Kali's link token has expired; the platform renews it while the Kali runs and the link is on");
  const kaliName = str(o.kali_name).replace(/[^A-Za-z0-9 ._()#-]/g, "").slice(0, 80) || "this Kali";
  return { link: { base, token, expiresAt: o.expires_at, kaliId: Number(o.kali_id) || 0, kaliName }, present: true, problem: "" };
}

export type Auth = { base: string; token: string; local: boolean; source: "manual" | "link" | "none" };

/** A token typed by hand ALWAYS wins (with the settings' base); else a valid link (ITS base, https only). */
export function chooseAuth(settingsBase: string, manualToken: string, local: boolean, link: KaliLinkResult): Auth {
  if (manualToken && manualToken.trim()) return { base: settingsBase, token: manualToken.trim(), local, source: "manual" };
  if (link.link) return { base: link.link.base, token: link.link.token, local: false, source: "link" };
  return { base: settingsBase, token: "", local, source: "none" };
}

/** What the page says about the token in use. Never the token itself. */
export function tokenStateText(source: Auth["source"], link: KaliLinkResult): string {
  if (source === "manual") return "token set by you";
  if (source === "link" && link.link) return `Connected automatically through this Kali's Privara link (${link.link.kaliName})`;
  if (link.present) return `no token set (${link.problem})`;
  return "no token set";
}

/** Remove the token (and anything bearer-shaped) from text before it is shown or logged. */
export function scrub(text: string, token: string): string {
  let s = str(text);
  if (token && token.length >= 4) s = s.split(token).join("<token>");
  s = s.replace(/(bearer\s+)[A-Za-z0-9._~+/=-]{6,}/gi, "$1<token>");
  s = s.replace(/(authorization\s*[:=]\s*)\S+/gi, "$1<token>");
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

/**
 * What the page shows for a failed backend call. Caido (0.59, tested 2026-11-12) delivers a backend
 * throw to the frontend as "RPC function 'name' threw an error: <message> at fn (plugin:L:C) at ...":
 * keep only the message, so a tester sees the reason and not the plugin's stack.
 */
export function cleanError(raw: unknown): string {
  let s = str(raw instanceof Error ? raw.message : raw);
  s = s.replace(/^RPC function '[^']*' threw an error:\s*/, "");
  s = s.replace(/\s+at\s+\S*\s*\(plugin:\d+:\d+\)[\s\S]*$/, "");
  s = s.replace(/\s+at\s+plugin:\d+:\d+[\s\S]*$/, "");
  return s.trim() || "the call failed";
}

/** FastAPI's {"detail": ...}, else the start of the body. */
export function detailOf(body: string): string {
  try {
    const d = obj(JSON.parse(body)).detail;
    if (typeof d === "string") return d;
    if (d !== undefined) return JSON.stringify(d);
  } catch {
    /* not JSON */
  }
  return body.slice(0, 300);
}

export function isAnalysisDevice(d: Obj): boolean {
  return arr(d.capabilities).includes("ipa_analysis");
}

// ------------------------------------------------------------------ hosts

export function hostClean(h: unknown): string | null {
  let x = str(h).trim().toLowerCase();
  while (x.endsWith(".")) x = x.slice(0, -1);
  const c = x.indexOf(":");
  if (c >= 0 && c === x.lastIndexOf(":")) x = x.slice(0, c);
  if (!x || x.includes("..") || !HOST_RE.test(x)) return null;
  return x;
}

export function hostAllowed(host: string, patterns: string[]): boolean {
  let h = (host || "").toLowerCase();
  while (h.endsWith(".")) h = h.slice(0, -1);
  if (!h) return false;
  for (const p0 of patterns || []) {
    const p = str(p0).toLowerCase();
    if (p.startsWith("*.")) {
      if (h.endsWith(p.slice(1)) && h !== p.slice(2)) return true;
    } else if (h === p) {
      return true;
    }
  }
  return false;
}

/** The host in one burp-scope.json include regex ("^" + re.escape(host) + "$"), or null. */
export function fromScopeRegex(rx: string): string | null {
  if (!rx || !rx.startsWith("^") || !rx.endsWith("$") || rx.length < 3) return null;
  const body = rx.slice(1, -1);
  let out = "";
  for (let i = 0; i < body.length; i++) {
    const c = body[i]!;
    if (c === "\\") {
      const n = body[++i];
      if (n !== "." && n !== "-") return null;
      out += n;
    } else if (".*+?()[]|{}^$".includes(c)) {
      return null;
    } else {
      out += c;
    }
  }
  const h = hostClean(out);
  return h !== null && h === out.toLowerCase() ? h : null;
}

// ------------------------------------------------------------------ API map

export type Endpoint = {
  scheme: "https" | "http";
  host: string;
  method: string;
  path: string;
  query: string[];
  note: string;
  inScope: boolean;
};

export type ApiMap = { endpoints: Endpoint[]; hosts: string[]; inScopeHosts: string[]; notes: string[]; title: string };

export function scopeHosts(burpScopeJson: string | null): string[] {
  if (burpScopeJson === null) return [];
  const scope = obj(obj(obj(JSON.parse(burpScopeJson)).target).scope);
  const out = new Set<string>();
  for (const inc of arr(scope.include)) {
    const i = obj(inc);
    if (i.enabled !== true) continue;
    const h = fromScopeRegex(str(i.host));
    if (h) out.add(h);
  }
  return [...out].sort();
}

function servers(list: unknown): Array<[Endpoint["scheme"], string]> {
  const out: Array<[Endpoint["scheme"], string]> = [];
  for (const s of arr(list)) {
    const url = str(obj(s).url);
    const m = /^(https?):\/\/(.*?)\/?$/.exec(url);
    if (!m) continue;
    const h = hostClean(m[2]);
    if (h && h === m[2]!.toLowerCase()) out.push([m[1] as Endpoint["scheme"], h]);
  }
  return out;
}

export function parseApiMap(openapiJson: string | null, burpScopeJson: string | null): ApiMap {
  const notes: string[] = [];
  const inScopeHosts = scopeHosts(burpScopeJson);
  const inSet = new Set(inScopeHosts);
  if (burpScopeJson === null) {
    notes.push("the bundle has no burp-scope.json (no apimap run?), so no host is treated as in scope");
  } else if (!inScopeHosts.length) {
    notes.push("no host is in scope: the iOS device has no engagement scope, or none of the app's first-party hosts is in it");
  }
  if (openapiJson === null) {
    notes.push("the bundle has no openapi.json: run apimap on the upload first");
    return { endpoints: [], hosts: [], inScopeHosts, notes, title: "" };
  }
  const doc = obj(JSON.parse(openapiJson));
  const top = servers(doc.servers);
  const hosts = new Set(top.map((s) => s[1]));
  const endpoints: Endpoint[] = [];
  let dropped = 0;
  for (const [path, itemV] of Object.entries(obj(doc.paths))) {
    if (!PATH_RE.test(path)) {
      dropped++;
      continue;
    }
    const item = obj(itemV);
    const srv = "servers" in item ? servers(item.servers) : top;
    for (const [mk, opV] of Object.entries(item)) {
      const method = mk.toUpperCase();
      if (!METHODS.includes(method)) continue;
      const op = obj(opV);
      const query: string[] = [];
      for (const pv of arr(op.parameters)) {
        const p = obj(pv);
        const name = str(p.name);
        if (str(p.in) === "query" && PARAM_RE.test(name) && !query.includes(name)) query.push(name);
      }
      for (const [scheme, host] of srv) {
        endpoints.push({ scheme, host, method, path, query, note: str(op.description), inScope: inSet.has(host) });
        hosts.add(host);
      }
    }
  }
  if (dropped) notes.push(`${dropped} path(s) with unusable characters were left out`);
  endpoints.sort((a, b) => a.host.localeCompare(b.host) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  return { endpoints, hosts: [...hosts].sort(), inScopeHosts, notes, title: str(obj(doc.info).title) };
}

export function target(e: Endpoint): string {
  return e.query.length ? `${e.path}?${e.query.map((q) => q + "=").join("&")}` : e.path;
}

/** A raw HTTP/1.1 request for Replay. Nothing in it was observed on the wire. */
export function rawRequest(e: Endpoint): string {
  let r = `${e.method} ${target(e)} HTTP/1.1\r\nHost: ${e.host}\r\nAccept: */*\r\n`;
  r += `User-Agent: privara-caido/${VERSION} (static map stub)\r\n`;
  if (e.method === "POST" || e.method === "PUT" || e.method === "PATCH") {
    r += "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
  } else {
    r += "\r\n";
  }
  return r;
}

// ------------------------------------------------------------------ request forging

export type HostState = { host: string; enabled: boolean; scope: string; note: string };
export type Decision = { sign: boolean; reason: string };

export class ApiError extends Error {
  status: number;
  detail: string;
  constructor(status: number, detail: string) {
    super(status ? `HTTP ${status}: ${detail}` : detail);
    this.status = status;
    this.detail = detail;
  }
}

export const BACKOFF_MS = 60_000;

export class ForgeGate {
  on = false;
  harnessId = 0;
  harnessName = "";
  patterns: string[] = [];
  harnessNote = "load the forge status first";
  hosts = new Map<string, HostState>();
  private backoffUntil = 0;
  private tokens = 30;
  private capacity = 30;
  private perMs = 120 / 60_000;
  private lastRefill: number;
  private clock: () => number;

  constructor(clock: () => number = () => Date.now()) {
    this.clock = clock;
    this.lastRefill = clock();
  }

  reset(why: string): void {
    this.on = false;
    this.clear(why);
  }

  private clear(why: string): void {
    this.harnessId = 0;
    this.harnessName = "";
    this.patterns = [];
    this.harnessNote = why;
    this.hosts.clear();
  }

  loadStatus(status: Obj, wantId: number): void {
    const sel = Number(status.selected || 0);
    let pick: Obj | null = null;
    for (const hv of arr(status.harnesses)) {
      const h = obj(hv);
      const id = Number(h.id || 0);
      if ((wantId > 0 && id === wantId) || (wantId <= 0 && id === sel)) pick = h;
    }
    const lim = obj(status.limits);
    this.capacity = Math.max(1, Number(lim.burst || 30));
    this.perMs = Math.max(1, Number(lim.per_minute || 120)) / 60_000;
    this.tokens = Math.min(this.tokens, this.capacity);
    if (!pick) {
      this.clear(wantId > 0 ? `harness ${wantId} is not on this device` : "no harness is selected on this device (privara ipa forge use)");
      return;
    }
    if (pick.verified !== true) {
      this.clear(`harness ${str(pick.name)} is not verified: only a verified harness signs (privara ipa forge verify)`);
      return;
    }
    this.harnessId = Number(pick.id);
    this.harnessName = str(pick.name);
    this.patterns = arr(obj(pick.meta).hosts)
      .map((p) => str(p).trim().toLowerCase())
      .filter((p) => {
        const core = p.startsWith("*.") ? p.slice(2) : p;
        return hostClean(core) === core;
      });
    this.harnessNote = `harness ${this.harnessName} #${this.harnessId} (verified)`;
    for (const k of [...this.hosts.keys()]) if (!hostAllowed(k, this.patterns)) this.hosts.delete(k);
    for (const p of this.patterns) {
      if (!p.startsWith("*.") && !this.hosts.has(p)) this.hosts.set(p, { host: p, enabled: false, scope: "", note: "" });
    }
  }

  /** scopeCheck is the server's answer to GET .../scope?target=<host>. null = enabled, else why not. */
  enable(host: string, scopeCheck: Obj | null): string | null {
    const h = hostClean(host);
    if (!h || h !== (host || "").trim().toLowerCase()) return "not a plain host name";
    if (!this.harnessId) return this.harnessNote;
    if (!hostAllowed(h, this.patterns)) return `${h} is not one of the harness's HOSTS ${JSON.stringify(this.patterns)}`;
    let st = this.hosts.get(h);
    if (!st) {
      st = { host: h, enabled: false, scope: "", note: "" };
      this.hosts.set(h, st);
    }
    const scope = scopeCheck ? scopeCheck.scope : null;
    if (scope === null || scope === undefined || str(scope) === "") {
      st.enabled = false;
      st.note = "no engagement scope on the iOS device: signing is refused without one";
      return st.note;
    }
    st.scope = str(scope);
    if (scopeCheck!.allowed !== true) {
      st.enabled = false;
      st.note = `outside the engagement scope '${st.scope}'`;
      return st.note;
    }
    st.enabled = true;
    st.note = `in scope '${st.scope}'`;
    return null;
  }

  disable(host: string, why: string): void {
    const st = this.hosts.get(hostClean(host) || "");
    if (st) {
      st.enabled = false;
      st.note = why;
    }
  }

  candidate(host: string): boolean {
    if (!this.on || !this.harnessId) return false;
    const h = hostClean(host);
    const st = h ? this.hosts.get(h) : undefined;
    return !!(st && st.enabled && hostAllowed(h!, this.patterns));
  }

  decide(host: string): Decision {
    if (!this.on) return { sign: false, reason: "forging is off" };
    const h = hostClean(host);
    if (!h) return { sign: false, reason: "not a plain host" };
    if (!this.harnessId) return { sign: false, reason: this.harnessNote };
    if (!hostAllowed(h, this.patterns)) return { sign: false, reason: "not a harness host" };
    const st = this.hosts.get(h);
    if (!st || !st.enabled) return { sign: false, reason: "host not enabled for forging" };
    const now = this.clock();
    if (now < this.backoffUntil) return { sign: false, reason: "the platform's signing limit was reached; backing off" };
    this.tokens = Math.min(this.capacity, this.tokens + (now - this.lastRefill) * this.perMs);
    this.lastRefill = now;
    if (this.tokens < 1) return { sign: false, reason: "client-side rate limit (the platform's own numbers)" };
    this.tokens -= 1;
    return { sign: true, reason: "sign" };
  }

  /** React to a refusal from the sign API so the same request is not tried again in vain. */
  onRefusal(host: string, e: ApiError): string {
    const d = e.detail.toLowerCase();
    if (e.status === 401) {
      this.on = false;
      return "the token was refused (HTTP 401): forging switched off";
    }
    if (e.status === 403) {
      this.on = false;
      return "iOS Analysis is not enabled for this account (HTTP 403): forging switched off";
    }
    if (d.includes("not verified")) {
      this.clear("the platform says the harness is not verified any more: reload and verify");
      return this.harnessNote;
    }
    if (d.includes("switched off on this platform")) {
      this.on = false;
      return "request signing is switched off on the platform: forging switched off";
    }
    if (d.includes("signing limit reached")) {
      this.backoffUntil = this.clock() + BACKOFF_MS;
      return "the platform's signing limit was reached: backing off for 60 s";
    }
    if (d.includes("no engagement scope") || d.includes("outside this device's engagement scope") ||
        d.includes("not one of this harness's hosts")) {
      this.disable(host, "refused by the platform: " + scrub(e.detail, "").slice(0, 160));
      return `refused for ${host}: host disabled`;
    }
    return "sign refused: " + scrub(e.detail, "").slice(0, 200);
  }
}

export type SignAnswer = { set: Array<[string, string]>; remove: string[]; body: Uint8Array | null };

/** Validate the sign API's answer before any of it touches a request. */
export function checkSignAnswer(res: Obj): SignAnswer {
  if (res.ok !== true) throw new Error("the signer failed: " + str(res.error));
  const set: Array<[string, string]> = [];
  for (const [k, v] of Object.entries(obj(res.headers))) {
    const val = str(v);
    if (!HEADER_NAME_RE.test(k) || /[\r\n]/.test(val)) throw new Error("the signer returned an unusable header; request left unsigned");
    set.push([k, val]);
  }
  const remove = arr(res.remove).map(str).filter((n) => HEADER_NAME_RE.test(n));
  const body = res.body_b64 === undefined || res.body_b64 === null ? null : b64decode(str(res.body_b64));
  return { set, remove, body };
}

// ------------------------------------------------------------------ findings

export const FINDINGS_SCHEMA = "privara.ios.findings/1";
export type Finding = { id: string; code: string; title: string; severity: string; confidence: string; description: string; remediation: string };

export function parseFindings(model: Obj): { findings: Finding[]; app: string; artifact: string; emptyReason: string } {
  if (str(model.schema) !== FINDINGS_SCHEMA) throw new Error(`not a Privara findings report (schema '${str(model.schema)}')`);
  const app = obj(model.app);
  return {
    findings: arr(model.findings).map((fv) => {
      const f = obj(fv);
      return {
        id: str(f.id), code: str(f.code), title: str(f.title), severity: str(f.severity).toLowerCase(),
        confidence: str(f.confidence), description: str(f.description), remediation: str(f.remediation),
      };
    }),
    app: str(app.name) || str(app.bundle_id),
    artifact: str(model.artifact),
    emptyReason: str(model.empty_reason),
  };
}

// ------------------------------------------------------------------ bytes

export function utf8(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    let c = s.charCodeAt(i);
    if (c >= 0xd800 && c < 0xdc00 && i + 1 < s.length) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d < 0xe000) {
        c = 0x10000 + ((c - 0xd800) << 10) + (d - 0xdc00);
        i++;
      }
    }
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return Uint8Array.from(out);
}

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function b64encode(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 3) {
    const n = (b[i]! << 16) | ((b[i + 1] ?? 0) << 8) | (b[i + 2] ?? 0);
    s += B64[(n >> 18) & 63]! + B64[(n >> 12) & 63]! + (i + 1 < b.length ? B64[(n >> 6) & 63]! : "=") +
      (i + 2 < b.length ? B64[n & 63]! : "=");
  }
  return s;
}

export function b64decode(s: string): Uint8Array {
  const clean = s.replace(/=+$/, "");
  if (/[^A-Za-z0-9+/]/.test(clean)) throw new Error("not base64");
  const out: number[] = [];
  let buf = 0;
  let bits = 0;
  for (const ch of clean) {
    buf = (buf << 6) | B64.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((buf >> bits) & 255);
    }
  }
  return Uint8Array.from(out);
}
