// server.js — BLE-TRIPWIRE standalone (on-device / Android nodejs-mobile build)
//
// Minimal Express server for the on-device pipeline. Exactly three jobs:
//   1) express.json body parsing (for the ESP32 ingest POST)
//   2) the BLE-TRIPWIRE route pipeline (installTripwire)
//   3) an app.listen on 0.0.0.0 so the phone-hotspot ESP32s can reach it
//
// Auth: the original Cloudflare deployment sat behind HTTP Basic auth. On-device
// the server is bound to the loopback/hotspot interfaces of the phone itself and
// the only client is the in-app WebView (loopback) plus the operator's own
// sensor nodes on the hotspot LAN, so Basic auth is intentionally removed. The
// audit chain's actorOf() degrades to "unauthenticated", which is accurate for a
// single-operator device.

import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Port: fixed default 8734 (uncommon, to avoid colliding with other localhost
// services). Overridable via env/argv (main.js forwards argv -> env). If you
// change this you must also change it in the ESP32 sketches' serverUrl and in
// the WebView URL in MainActivity/NodeService.
const PORT = Number(process.env.BLE_TRIPWIRE_PORT || 8734);

app.use(express.json({ limit: "50mb" }));

// Permissive CORS. Not strictly required when the WebView loads the dashboard
// from this same origin (the normal case), but it costs nothing and keeps the
// dashboard usable if it is ever loaded from file:// or an external browser on
// the hotspot LAN pointed at the phone.
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Actor");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Readiness probe. The Android Activity polls this until it returns 200 before
// pointing the WebView at the dashboard, so the UI never loads against a
// not-yet-listening server.
app.get("/health", (_req, res) => {
  res.json({ ok: true, service: "ble-tripwire", port: PORT, ts: new Date().toISOString() });
});

// Static dashboard (the WebView UI) + everything else the page references.
app.use(express.static(path.join(__dirname, "public")));

// Root -> the dashboard.
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// --- BLE-TRIPWIRE: ingest + Maven-style intel pipeline (unchanged core) ---
const { installTripwire } = await import("./lib/tripwire-intel.js");
installTripwire(app);

app.listen(PORT, "0.0.0.0", () => {
  console.log(`[BLE-TRIPWIRE] standalone server listening on http://0.0.0.0:${PORT}`);
  console.log(`[BLE-TRIPWIRE] dashboard: http://127.0.0.1:${PORT}/dashboard.html`);
  console.log(`[BLE-TRIPWIRE] ingest:    POST http://<phone-hotspot-ip>:${PORT}/api/sensors/ble-tripwire`);
  console.log(`[BLE-TRIPWIRE] data dir:  ${process.env.BLE_TRIPWIRE_DATA_DIR || "(default project data dir)"}`);
});
