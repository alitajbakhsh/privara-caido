# Privara iOS kit for Caido

A Caido plugin that brings **Privara iOS Analysis** into Caido: the backend API map of an iOS app,
scoped to your engagement, as Replay sessions and a Caido scope; the app's findings in a table; and
analyst-assisted request signing for apps that sign their API requests.

## Before you install: what this plugin needs (store disclosures)

- **An external service.** The plugin is a client of the **Privara platform** (TAJ APPS LLC,
  [tajapps.com](https://tajapps.com)), at the base URL you set (default `https://app.tajapps.com`).
  It does nothing without it: the analysis runs on the platform, not in Caido.
- **An account.** You need a Privara account with **iOS Analysis** and your own Privara API token.
- **Payment.** Privara iOS Analysis is a paid service.
- No telemetry, no ads, no self-update, and no assets loaded from the internet. The only network
  calls are the Privara API calls listed below, made when you act.

## What it does

- **Device and runs.** Pick an iOS Analysis device, run `apimap`, `cloudcheck` or `deeplinks` on a
  file already uploaded to it, pick a run.
- **API map.** Import the run's map. **Send to Replay** opens a request stub as a Replay session
  (nothing is sent until you send it), for hosts in the device's engagement scope only. **Create a
  Caido scope** from the hosts the platform found in that scope; a device with no scope adds none.
- **Request forging** (off until you switch it on). Requests to the hosts you tick are signed by
  the platform before Caido sends them, through Caido's upstream-plugin hook (add the plugin under
  **Settings > Network > Upstream Plugins** for those hosts). Each host is scope-checked first;
  any other request never reaches the platform.
- **Findings.** The run's static-analysis findings in a table (not runtime proof).

## What leaves Caido, and where it goes

Only to the Privara base URL you set, only when you act, with Caido's own `fetch`:

| You do | Sent |
|---|---|
| Test connection, refresh devices / runs | your API token (Authorization header) |
| Run analysis | the analysis name and the uploaded file's path |
| Import, findings | the run id |
| Tick a forging host | the host name (scope check) |
| Forging on: a request to a ticked host | that request's method, URL, headers and body, to be signed |

- The token is stored in this plugin's own database in Caido's data folder on this machine (not
  encrypted), never shown to the page again, never logged, and sent only in the Authorization
  header to the base URL. Calls use Caido's `fetch`, so they never appear in Caido's HTTP history.
- `https://` only; `http://` for `localhost` alone, with an explicit development box ticked.
- On a Privara cloud Kali with no token typed, the backend reads that Kali's short-lived,
  root-only link file (`/etc/privara/kali-link.json`, read only). A typed token always wins.

## Install

1. Caido **Plugins > Community Store > Privara iOS kit > Install** (or **Plugins > Install
   package** with a release's `plugin_package.zip`).
2. Open **Privara** in the sidebar: base URL, your API token (Privara: **API** page > **Generate
   token**), Save, Test connection.

## Build

Node 23 or later.

```
./build.sh       # npm ci (exact versions), unit tests, typecheck, caido-dev build -> dist/plugin_package.zip
```

The package is normalised (fixed order and timestamp), so the same sources give the same bytes.

## Third-party code

The backend bundles [fflate](https://github.com/101arrowz/fflate) 0.8.2 to read the analysis
bundle (zip): MIT License, Copyright (c) 2023 Arjun Barrett. The build uses
`@caido/sdk-backend`, `@caido/sdk-frontend` and `@caido-community/dev` (Caido's SDK) and
TypeScript; they are not shipped.

## Licence

See [LICENSE](LICENSE).
