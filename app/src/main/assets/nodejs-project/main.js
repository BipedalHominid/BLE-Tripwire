// main.js — nodejs-mobile entrypoint.
//
// The Android native bridge starts Node as:
//     node  main.js  <writable_data_dir>  <port>
// (argv[0]="node" is supplied by node::Start; argv[1]=this file.)
//
// We translate those arguments into the environment the pipeline reads, then
// hand off to server.js. Doing this here — before server.js dynamically imports
// the pipeline — guarantees the env is set before the pipeline computes its
// data-dir constants at import time.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const dataDir = process.argv[2];
const port = process.argv[3];

if (dataDir) process.env.BLE_TRIPWIRE_DATA_DIR = dataDir;
if (port) process.env.BLE_TRIPWIRE_PORT = port;

// Per-install random secrets, generated on first launch and persisted in the
// app's private data directory. This means every install gets a unique HMAC
// anonymization salt and a unique audit-chain key — nothing is shared with, or
// derivable from, the public source code.
function ensureSecret(envName, fileName) {
  if (process.env[envName]) return; // explicit override wins
  const base = process.env.BLE_TRIPWIRE_DATA_DIR;
  if (!base) return; // desktop/dev run without a data dir: pipeline default applies
  try {
    fs.mkdirSync(base, { recursive: true });
    const f = path.join(base, fileName);
    let secret;
    if (fs.existsSync(f)) {
      secret = fs.readFileSync(f, "utf8").trim();
    }
    if (!secret) {
      secret = crypto.randomBytes(32).toString("hex");
      fs.writeFileSync(f, secret, { encoding: "utf8", mode: 0o600 });
    }
    process.env[envName] = secret;
  } catch (e) {
    console.warn(`[BLE-TRIPWIRE] could not provision ${envName}: ${e.message}`);
  }
}

ensureSecret("BLE_TRIPWIRE_HMAC_SECRET", ".hmac.secret");
ensureSecret("BLE_TRIPWIRE_AUDIT_SECRET", ".audit.secret");

process.on("uncaughtException", (e) => {
  console.error("[BLE-TRIPWIRE] uncaughtException:", e && e.stack ? e.stack : e);
});
process.on("unhandledRejection", (e) => {
  console.error("[BLE-TRIPWIRE] unhandledRejection:", e && e.stack ? e.stack : e);
});

console.log("[BLE-TRIPWIRE] main.js boot; dataDir=" + (dataDir || "(default)") + " port=" + (port || "(default)"));

await import("./server.js");
