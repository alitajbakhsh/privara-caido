// EVERY Privara API call this plugin makes, in the same parseable shape as the Burp extension's
// Endpoints.java:  "METHOD /api/path/{iid}/... [?query,params] [{body,keys}]".
// The platform's contract test checks each one against its route table. Nothing else in
// the plugin may spell an API path.

export const EP = {
  WHOAMI: "GET /api/whoami",
  DEVICES: "GET /api/instances",
  SCAN: "POST /api/instances/{iid}/ipa/scan {op,path}",
  RUNS: "GET /api/instances/{iid}/ipa/runs ?limit",
  BUNDLE: "GET /api/instances/{iid}/ipa/runs/{rid}/bundle",
  REPORT: "GET /api/instances/{iid}/ipa/report ?run_id,upload,format",
  SCOPE_CHECK: "GET /api/instances/{iid}/scope ?target",
  FORGE_STATUS: "GET /api/instances/{iid}/ipa/forge",
  FORGE_SIGN: "POST /api/instances/{iid}/ipa/forge/sign {harness_id,request}",
} as const;

export function method(ep: string): string {
  return ep.slice(0, ep.indexOf(" "));
}

/** The path with {iid} / {rid} filled in. Only integers go in. */
export function path(ep: string, iid = 0, rid = 0): string {
  const rest = ep.slice(ep.indexOf(" ") + 1);
  const p = rest.includes(" ") ? rest.slice(0, rest.indexOf(" ")) : rest;
  return p.replace("{iid}", String(Math.trunc(iid))).replace("{rid}", String(Math.trunc(rid)));
}
