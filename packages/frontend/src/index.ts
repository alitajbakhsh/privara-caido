// Privara iOS kit for Caido -- frontend (the "Privara" page in Caido's sidebar).
// Plain DOM, no framework. Every Privara call goes through the backend plugin, which holds the
// token; this page never sees it after it is saved.

import type { Caido } from "@caido/sdk-frontend";
import type { API } from "../../backend/src/index";
import { cleanError } from "../../backend/src/core";

type SDK = Caido<API>;
type Endpoint = { scheme: string; host: string; method: string; path: string; query: string[]; note: string; inScope: boolean };

function el<K extends keyof HTMLElementTagNameMap>(tag: K, attrs: Record<string, string> = {}, ...kids: Array<Node | string>) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  for (const k of kids) e.append(k);
  return e;
}

function button(text: string, fn: () => Promise<void> | void, status: HTMLElement): HTMLButtonElement {
  const b = el("button", { class: "c-button" }, text);
  b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await fn();
    } catch (e) {
      // Caido wraps a backend throw as "RPC function '...' threw an error: <message> at ... (plugin:L:C)".
      status.textContent = cleanError(e);
    } finally {
      b.disabled = false;
    }
  });
  return b;
}

function section(title: string, ...kids: Array<Node | string>): HTMLElement {
  return el("section", { style: "margin:12px 0;padding:10px;border:1px solid var(--c-border-default,#444);border-radius:6px" },
    el("h3", { style: "margin:0 0 8px" }, title), ...kids);
}

function row(...kids: Array<Node | string>): HTMLElement {
  return el("div", { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:4px 0" }, ...kids);
}

export const init = (sdk: SDK) => {
  const root = el("div", { style: "padding:12px;overflow:auto;height:100%" });

  // ---------------------------------------------------------------- settings
  const base = el("input", { size: "40", placeholder: "https://app.tajapps.com" });
  const token = el("input", { type: "password", size: "40", placeholder: "paste your Privara API token" });
  const local = el("input", { type: "checkbox" });
  const tokenState = el("span");
  const sStatus = el("div");
  void sdk.backend.getSettings().then((s) => {
    base.value = s.baseUrl;
    local.checked = s.allowLocalhostHttp;
    tokenState.textContent = s.tokenState;
  });
  root.append(section("Settings",
    row("Privara base URL", base),
    row("Your API token", token, tokenState),
    row(local, "Allow http://localhost (development only; real platforms are https)"),
    row(button("Save", async () => {
      const s = await sdk.backend.saveSettings(base.value, token.value, local.checked);
      token.value = "";
      tokenState.textContent = s.tokenState;
      sStatus.textContent = "saved";
    }, sStatus), button("Test connection", async () => {
      sStatus.textContent = "signed in as " + (await sdk.backend.testConnection());
    }, sStatus), button("Forget token", async () => {
      const s = await sdk.backend.forgetToken();
      tokenState.textContent = s.tokenState;
      sStatus.textContent = "token forgotten; forging switched off";
    }, sStatus), button("Use this Kali's link", async () => {
      const s = await sdk.backend.useKaliLink();
      tokenState.textContent = s.tokenState;
      sStatus.textContent = s.tokenSource === "link"
        ? "using this Kali's Privara link; forging switched off"
        : "typed token dropped; " + (s.tokenState.startsWith("no token set (") ? s.tokenState.slice(14, -1)
          : "there is no Privara link here (it exists only on a Privara cloud Kali with the link on)");
    }, sStatus)),
    sStatus,
    el("p", {}, "On a Privara cloud Kali you need no token: the plugin uses this Kali's Privara link. " +
      "Elsewhere, create one on the platform: API page (sidebar) > Generate token. A token typed here always wins over the link. " +
      "The token is kept by this plugin's backend and sent only to the base URL above, in the Authorization header. " +
      "It is never shown again and never logged.")));

  let clearFindings = () => undefined as void;

  // ---------------------------------------------------------------- device, runs, API map
  const devices = el("select");
  const runs = el("select");
  const op = el("select");
  for (const o of ["apimap", "cloudcheck", "deeplinks"]) op.append(el("option", { value: o }, o));
  const guestPath = el("input", { size: "50", placeholder: "the uploaded file on the device (privara ipa upload prints it)" });
  const dStatus = el("div");
  const showOutside = el("input", { type: "checkbox" });
  const table = el("table", { style: "width:100%;border-collapse:collapse" });
  let map: { endpoints: Endpoint[]; inScopeHosts: string[]; raws: string[]; notes: string[]; title: string } | null = null;

  const renderMap = () => {
    table.replaceChildren(el("tr", {}, ...["In scope", "Method", "Host", "Path", "Query", ""].map((h) => el("th", { style: "text-align:left" }, h))));
    if (!map) return;
    map.endpoints.forEach((e, i) => {
      if (!e.inScope && !showOutside.checked) return;
      const send = button("Send to Replay", async () => {
        if (!e.inScope) {
          dStatus.textContent = "refused: outside the device's engagement scope";
          return;
        }
        try {
          await sdk.replay.createSession({ type: "Raw", raw: map!.raws[i]!, connectionInfo: { host: e.host, port: e.scheme === "http" ? 80 : 443, isTLS: e.scheme !== "http" } });
        } catch (err) {
          // Caido 0.59 with no project open: "Could not acquire a connection to the database".
          dStatus.textContent = "Caido did not create the Replay session (is a project open?): " + cleanError(err);
          return;
        }
        dStatus.textContent = `${e.method} ${e.path} sent to Replay`;
      }, dStatus);
      send.disabled = !e.inScope;
      table.append(el("tr", {}, el("td", {}, e.inScope ? "yes" : "NO"), el("td", {}, e.method), el("td", {}, e.host),
        el("td", {}, e.path), el("td", {}, e.query.join(", ")), el("td", {}, send)));
    });
  };
  showOutside.addEventListener("change", renderMap);

  root.append(section("Device & API map",
    row("iOS Analysis device", devices, button("Refresh devices", async () => {
      const list = await sdk.backend.devices();
      const s = await sdk.backend.getSettings();
      devices.replaceChildren(...list.map((d) => {
        const o = el("option", { value: String(d.id) }, `${d.name} (#${d.id}, ${d.status}, scope ${d.scope || "none"})`);
        if (d.id === s.deviceId) o.selected = true;
        return o;
      }));
      if (list.length && Number(devices.value) !== s.deviceId) {
        await sdk.backend.setDevice(Number(devices.value));
        clearDeviceState();
      }
      dStatus.textContent = list.length ? `${list.length} iOS Analysis device(s)` : "no iOS Analysis device on this account";
    }, dStatus)),
    row("Analysis", op, guestPath, button("Run", async () => {
      const r = await sdk.backend.runOp(op.value, guestPath.value.trim());
      dStatus.textContent = `${op.value} ${r.ok ? "finished" : "failed: " + String(r.error ?? "")}`;
    }, dStatus)),
    row("Run", runs, button("Refresh runs", async () => {
      const list = await sdk.backend.runs();
      runs.replaceChildren(...list.map((r) => el("option", { value: String(r.id) }, `#${r.seq} ${r.op} ${r.artifact}`)));
    }, dStatus), button("Import API map", async () => {
      map = await sdk.backend.importMap(Number(runs.value));
      renderMap();
      dStatus.textContent = `${map.endpoints.length} endpoint(s); in the engagement scope: ${map.inScopeHosts.join(", ") || "none"}` +
        (map.notes.length ? " -- " + map.notes.join("; ") : "");
    }, dStatus), button("Create a Caido scope from the in-scope hosts", async () => {
      if (!map || !map.inScopeHosts.length) {
        dStatus.textContent = "nothing to add: no host is in the device's engagement scope";
        return;
      }
      // createScope answers undefined (it does not throw) when Caido could not make the scope, e.g.
      // with no project open (seen in Caido 0.59). Only a returned scope counts as created.
      const created = await sdk.scopes.createScope({ name: `Privara ${map.title || "iOS app"}`.slice(0, 80), allowlist: map.inScopeHosts, denylist: [] });
      if (!created) {
        dStatus.textContent = "Caido did not create the scope: open or create a Caido project first, then try again";
        return;
      }
      dStatus.textContent = "Caido scope created with: " + map.inScopeHosts.join(", ");
    }, dStatus)),
    row(showOutside, "Show first-party hosts OUTSIDE the engagement scope (never sent to Replay)"),
    dStatus, table));
  // A different device: its runs, map and findings are not the old device's. Clear them so nothing
  // (an in-scope host list, a run id) from the previous device is used against the new one.
  const clearDeviceState = () => {
    runs.replaceChildren();
    map = null;
    renderMap();
    clearFindings();
  };
  devices.addEventListener("change", async () => {
    if (!devices.value) return;
    const before = (await sdk.backend.getSettings()).deviceId;
    try {
      await sdk.backend.setDevice(Number(devices.value));
    } catch (e) {
      dStatus.textContent = cleanError(e);
      return;
    }
    if (Number(devices.value) !== before) {
      clearDeviceState();
      dStatus.textContent = "device changed: refresh its runs";
    }
  });

  // ---------------------------------------------------------------- request forging
  const fStatus = el("div");
  const harnessId = el("input", { size: "5", placeholder: "auto" });
  const forgeOn = el("input", { type: "checkbox" });
  const hostBox = el("input", { size: "30", placeholder: "host under a *.wildcard HOSTS entry" });
  const hosts = el("div");
  const counters = el("div");
  type FS = Awaited<ReturnType<SDK["backend"]["forgeState"]>>;
  const render = (s: FS) => {
    forgeOn.checked = s.on;
    counters.textContent = `${s.harness} | HOSTS ${s.patterns.join(", ")} | signed ${s.counters.signed}, failed ${s.counters.failed}, passed through ${s.counters.passed}` +
      (s.lastError ? ` | last problem: ${s.lastError}` : "");
    hosts.replaceChildren(...s.hosts.map((h) => {
      const cb = el("input", { type: "checkbox" });
      cb.checked = h.enabled;
      cb.addEventListener("change", async () => {
        const r = cb.checked ? await sdk.backend.forgeEnable(h.host) : await sdk.backend.forgeDisable(h.host);
        render(r);
        if (r.message) fStatus.textContent = r.message;
      });
      return row(cb, h.host, h.scope ? `scope ${h.scope}` : "", h.note);
    }));
    if (s.message) fStatus.textContent = s.message;
  };
  forgeOn.addEventListener("change", async () => render(await sdk.backend.forgeSwitch(forgeOn.checked)));
  root.append(section("Request forging (analyst-assisted)",
    el("p", {}, "Signs requests to the hosts you tick with the device's VERIFIED harness, through the platform's sign API. " +
      "Also add this plugin for those domains in Caido: Settings > Network > Upstream Plugins > Add Plugin. Every other request is untouched. " +
      "Ticking a host asks the platform whether it is in the engagement scope; the platform checks again on every sign."),
    row("Harness id", harnessId, button("Load forge status", async () => {
      render(await sdk.backend.forgeLoad(Number(harnessId.value || 0)));
    }, fStatus)),
    row(forgeOn, "Sign requests (request forging ON)"),
    row(hostBox, button("Add and check scope", async () => render(await sdk.backend.forgeEnable(hostBox.value.trim())), fStatus)),
    counters, hosts, fStatus));
  setInterval(() => void sdk.backend.forgeState().then(render).catch(() => undefined), 3000);

  // ---------------------------------------------------------------- findings
  const rStatus = el("div");
  const ftable = el("table", { style: "width:100%;border-collapse:collapse" });
  clearFindings = () => {
    ftable.replaceChildren();
    rStatus.textContent = "";
  };
  root.append(section("Findings",
    el("p", {}, "Static analysis of the iOS app bundle by Privara, not runtime proof. Caido findings must be attached to a " +
      "captured request, so these are listed here rather than created as Caido findings."),
    row(button("Load findings for the chosen run", async () => {
      const f = await sdk.backend.findings(Number(runs.value));
      ftable.replaceChildren(el("tr", {}, ...["Severity", "Title", "Code", "Confidence", "ID"].map((h) => el("th", { style: "text-align:left" }, h))),
        ...f.findings.map((x) => el("tr", { title: x.description }, el("td", {}, x.severity), el("td", {}, x.title), el("td", {}, x.code),
          el("td", {}, x.confidence), el("td", {}, x.id))));
      rStatus.textContent = `${f.findings.length} finding(s) for ${f.app} (${f.artifact})` + (f.emptyReason ? " -- " + f.emptyReason : "");
    }, rStatus)),
    rStatus, ftable));

  sdk.navigation.addPage("/privara", { body: root });
  sdk.sidebar.registerItem("Privara", "/privara", { icon: "fas fa-mobile-screen" });
};
