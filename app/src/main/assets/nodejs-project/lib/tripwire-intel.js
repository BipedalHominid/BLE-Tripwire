// lib/tripwire-intel.js
// BLE-TRIPWIRE BLE ingest + Maven-style intel pipeline.
// Pure ESM (no require). Faithful port of the original server.js block, with
// two additions: a data-sufficiency gate and a tamper-evident audit chain.
//
// Wire from server.js:
//   const { installTripwire } = await import("./lib/tripwire-intel.js");
//   installTripwire(app);
//
// PRESERVED FROM ORIGINAL (do not regress):
//   - HMAC-SHA256 anonymization (same secret -> same DEV- ids as existing data)
//   - raw_mac stored locally in observations.jsonl; only anonymized data leaves
//   - stty+exec serial PAUSE/RESUME to the ESP32
//   - exact /status, /toggle, ingest, /intel, /process response shapes
// ADDED:
//   - data-sufficiency gate on /process (no confident product on thin/stale data)
//   - HMAC-chained audit log + GET /audit/verify (NIST 800-53 AU)

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "..");

// ---- runtime state (preserved) --------------------------------------------
const tripwireKnownDevices = new Set();
let tripwireEnabled = process.env.BLE_TRIPWIRE_DEFAULT !== "0";


// ---- paths (resolve to the SAME data dir the original used) ----------------
// ON-DEVICE (Android/nodejs-mobile): the extracted asset tree can be read-only
// and is wiped on app upgrade, so the Android layer passes a stable writable
// dir (app filesDir) via BLE_TRIPWIRE_DATA_DIR. Desktop leaves it unset
// and gets the original PROJECT_ROOT/data/tripwire path — behaviour is
// identical to the original when the env var is absent.
const TRIPWIRE_DATA_DIR =
  process.env.BLE_TRIPWIRE_DATA_DIR ||
  path.join(PROJECT_ROOT, "data", "tripwire");
const TRIPWIRE_OBS_FILE = path.join(
  TRIPWIRE_DATA_DIR,
  "observations.jsonl"
);
const TRIPWIRE_INTEL_FILE = path.join(
  TRIPWIRE_DATA_DIR,
  "latest_report.json"
);
const TRIPWIRE_AUDIT_FILE = path.join(
  TRIPWIRE_DATA_DIR,
  "audit_chain.jsonl"
);

const TRIPWIRE_BASELINE_FILE = path.join(
  TRIPWIRE_DATA_DIR,
  "baseline.json"
);

// Custom device names (anonymized_id -> label), persisted across restarts.
const TRIPWIRE_NAMES_FILE = path.join(
  TRIPWIRE_DATA_DIR,
  "names.json"
);

// Arm state: when disarmed, sensing/history keep running but the notification
// poller is told to stay quiet. Also holds an optional daily schedule window.
const TRIPWIRE_ARM_FILE = path.join(
  TRIPWIRE_DATA_DIR,
  "arm.json"
);

// Anonymization salt (NOT request auth). Keep identical to existing installs
// so historical DEV- ids stay stable.
const TRIPWIRE_HMAC_SECRET =
  process.env.BLE_TRIPWIRE_HMAC_SECRET || "local-ble-tripwire-demo-secret";

// Audit-chain integrity key. For genuine tamper-evidence this MUST be set to a
// secret the would-be tamperer cannot read; with the demo default, anyone who
// knows that default can recompute the chain. Keep it OUT of the data dir.
const TRIPWIRE_AUDIT_SECRET =
  process.env.BLE_TRIPWIRE_AUDIT_SECRET || "local-ble-tripwire-audit-secret";
if (!process.env.BLE_TRIPWIRE_AUDIT_SECRET) {
  console.warn(
    "[BLE-TRIPWIRE] BLE_TRIPWIRE_AUDIT_SECRET not set — audit chain uses a public default key and is NOT tamper-proof against a knowledgeable attacker."
  );
}

const TRIPWIRE_WINDOW_MS = Number(
  process.env.BLE_TRIPWIRE_WINDOW_MS || 30 * 60 * 1000
);


// ---- ADDED: data-sufficiency thresholds -----------------------------------
const MIN_OBSERVATIONS = Number(process.env.BLE_TRIPWIRE_MIN_OBS || 3);
const MAX_DATA_AGE_MS =
  Number(process.env.BLE_TRIPWIRE_MAX_AGE_MIN || 30) * 60000;

// ===========================================================================
// Storage + normalization (preserved verbatim from original)
// ===========================================================================
function ensureTripwireDataDir() {
  fs.mkdirSync(TRIPWIRE_DATA_DIR, { recursive: true });
}

function anonymizeBluetoothId(raw) {
  const value = String(raw || "unknown").trim().toUpperCase();
  const digest = crypto
    .createHmac("sha256", TRIPWIRE_HMAC_SECRET)
    .update(value)
    .digest("hex")
    .slice(0, 10)
    .toUpperCase();
  return `DEV-${digest}`;
}

function safeNumber(value, fallback = null) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function parseServiceUuids(value) {
  if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
  if (typeof value === "string" && value.length) {
    return value
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeTripwireDevice(device, now) {
  const rawMac = String(
    device.mac ||
      device.address ||
      device.observed_address ||
      device.id ||
      "unknown"
  )
    .trim()
    .toUpperCase();

  const rssi = safeNumber(device.rssi ?? device.rssi_dbm, null);

  const manufacturerDataHex = device.manufacturer_data
    ? String(device.manufacturer_data).trim().toUpperCase()
    : "";
  const serviceUuids = parseServiceUuids(device.service_uuids ?? device.uuid_list);
  const txPowerDbm = safeNumber(device.tx_power ?? device.tx_power_dbm, null);
  const addressType = device.address_type ? String(device.address_type) : "unknown";

  return {
    ts: now,
    received_at: now,
    sensor_id: String(device.sensor_id || device.sensor || "ESP32-BLE-01"),
    zone: String(device.zone || "Unknown Zone"),
    raw_mac: rawMac,
    anonymized_id: anonymizeBluetoothId(rawMac),
    rssi_dbm: rssi,
    // Kept for backward compatibility with older firmware that put the
    // device name in this field; new firmware should use advertised_name.
    uuid: device.uuid ? String(device.uuid) : "",
    service_uuids: serviceUuids,
    advertised_name: device.name || device.advertised_name || "",
    manufacturer_data_present: Boolean(
      manufacturerDataHex || device.manufacturer_data_present || device.mfg
    ),
    manufacturer_data: manufacturerDataHex,
    address_type: addressType,
    tx_power_dbm: txPowerDbm,
    source: "ble-tripwire-esp32",
  };
}

function appendTripwireObservation(obs) {
  ensureTripwireDataDir();
  fs.appendFileSync(
    TRIPWIRE_OBS_FILE,
    `${JSON.stringify(obs)}\n`,
    "utf8"
  );
}

function readRecentTripwireObservations(windowMs = TRIPWIRE_WINDOW_MS) {
  ensureTripwireDataDir();
  if (!fs.existsSync(TRIPWIRE_OBS_FILE)) return [];

  const cutoff = Date.now() - windowMs;
  const lines = fs
    .readFileSync(TRIPWIRE_OBS_FILE, "utf8")
    .split("\n")
    .filter(Boolean)
    .slice(-3000);

  const records = [];
  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      const t = new Date(obj.received_at || obj.ts).getTime();
      if (Number.isFinite(t) && t >= cutoff) records.push(obj);
    } catch {
      // ignore malformed historical lines
    }
  }
  return records;
}

// A node is "live" if it posted an observation within the freshness window.
const TRIPWIRE_NODE_LIVE_MS =
  Number(process.env.BLE_TRIPWIRE_NODE_LIVE_SEC || 60) * 1000;

function nodesFromObservations(windowMs = 10 * 60 * 1000) {
  ensureTripwireDataDir();
  if (!fs.existsSync(TRIPWIRE_OBS_FILE)) return [];
  const cutoff = Date.now() - windowMs;
  const lines = fs
    .readFileSync(TRIPWIRE_OBS_FILE, "utf8")
    .split("\n").filter(Boolean).slice(-3000);

  const byNode = new Map();
  for (const line of lines) {
    try {
      const o = JSON.parse(line);
      const t = new Date(o.received_at || o.ts).getTime();
      if (!Number.isFinite(t) || t < cutoff) continue;
      const id = String(o.sensor_id || "unknown");
      const cur = byNode.get(id) || { lastMs: 0, count: 0 };
      cur.count += 1;
      if (t > cur.lastMs) cur.lastMs = t;
      byNode.set(id, cur);
    } catch { /* ignore malformed */ }
  }

  const now = Date.now();
  return Array.from(byNode.entries())
    .map(([id, v]) => ({
      id,
      last_seen: new Date(v.lastMs).toISOString(),
      observation_count: v.count,
      live: now - v.lastMs <= TRIPWIRE_NODE_LIVE_MS,
    }))
    .sort((a, b) => a.id.localeCompare(b.id));
}

function baselineDeviceLabel(d) {
  const name = String(d?.device_name || d?.advertised_name || "").trim();
  const anon = String(d?.anonymized_id || "unknown");
  const cls = String(d?.device_class_estimate || "BLE emitter");
  const persistence = String(d?.persistence_level || "unknown persistence");
  const proximity = String(d?.proximity_band || "unknown proximity");
  const rssi = d?.rssi_avg_dbm ?? "n/a";
  return `${name ? `${name} ` : ""}${anon}: ${cls}; ${persistence}; ${proximity}; avg RSSI ${rssi} dBm`;
}

function readTripwireBaseline() {
  ensureTripwireDataDir();
  if (!fs.existsSync(TRIPWIRE_BASELINE_FILE)) return null;

  try {
    return JSON.parse(fs.readFileSync(TRIPWIRE_BASELINE_FILE, "utf8"));
  } catch {
    return null;
  }
}

function writeTripwireBaseline(baseline) {
  ensureTripwireDataDir();
  fs.writeFileSync(
    TRIPWIRE_BASELINE_FILE,
    JSON.stringify(baseline, null, 2),
    "utf8"
  );
  return baseline;
}

function deleteTripwireBaseline() {
  ensureTripwireDataDir();
  if (fs.existsSync(TRIPWIRE_BASELINE_FILE)) {
    fs.unlinkSync(TRIPWIRE_BASELINE_FILE);
  }
}

// ---- custom device names -------------------------------------------------

function readTripwireNames() {
  try {
    if (!fs.existsSync(TRIPWIRE_NAMES_FILE)) return {};
    const obj = JSON.parse(fs.readFileSync(TRIPWIRE_NAMES_FILE, "utf8"));
    return obj && typeof obj === "object" ? obj : {};
  } catch {
    return {};
  }
}
function writeTripwireNames(map) {
  ensureTripwireDataDir();
  fs.writeFileSync(TRIPWIRE_NAMES_FILE, JSON.stringify(map, null, 2));
}
function setTripwireName(id, label) {
  const map = readTripwireNames();
  const clean = String(label || "").trim().slice(0, 40);
  if (clean) map[id] = clean;
  else delete map[id];
  writeTripwireNames(map);
  return map;
}

// ---- arm state + optional schedule --------------------------------------
// Shape: { armed: bool, schedule: { enabled: bool, start: "HH:MM", end: "HH:MM" } }
// Default is ARMED so a fresh install notifies out of the box.

function readTripwireArm() {
  try {
    if (!fs.existsSync(TRIPWIRE_ARM_FILE))
      return { armed: true, schedule: { enabled: false, start: "23:00", end: "06:00" } };
    const obj = JSON.parse(fs.readFileSync(TRIPWIRE_ARM_FILE, "utf8"));
    return {
      armed: obj.armed !== false,
      schedule: {
        enabled: !!(obj.schedule && obj.schedule.enabled),
        start: (obj.schedule && obj.schedule.start) || "23:00",
        end: (obj.schedule && obj.schedule.end) || "06:00",
      },
    };
  } catch {
    return { armed: true, schedule: { enabled: false, start: "23:00", end: "06:00" } };
  }
}
function writeTripwireArm(state) {
  ensureTripwireDataDir();
  fs.writeFileSync(TRIPWIRE_ARM_FILE, JSON.stringify(state, null, 2));
}
// Effective "should notifications fire right now": armed AND (no schedule, or
// current local time falls inside the schedule window). Handles windows that
// cross midnight (e.g. 23:00 -> 06:00).
function tripwireNotifyActive(state = readTripwireArm(), now = new Date()) {
  if (!state.armed) return false;
  const sch = state.schedule;
  if (!sch || !sch.enabled) return true;
  const [sh, sm] = String(sch.start).split(":").map(Number);
  const [eh, em] = String(sch.end).split(":").map(Number);
  if (![sh, sm, eh, em].every(Number.isFinite)) return true;
  const cur = now.getHours() * 60 + now.getMinutes();
  const s = sh * 60 + sm, e = eh * 60 + em;
  return s <= e ? (cur >= s && cur < e) : (cur >= s || cur < e);
}

function buildTripwireBaseline(analysis, actor = "unknown") {
  const devices = (analysis.devices || [])
    .filter((d) => d?.anonymized_id)
    .map((d) => ({
      anonymized_id: d.anonymized_id,
      device_name: d.device_name || "",
      device_class_estimate: d.device_class_estimate || "",
      observation_count: d.observation_count || 0,
      rssi_avg_dbm: d.rssi_avg_dbm ?? null,
      proximity_band: d.proximity_band || "",
      persistence_level: d.persistence_level || "",
      confidence: d.confidence || "",
      first_seen: d.first_seen || null,
      last_seen: d.last_seen || null,
    }));

  return {
    type: "TRIPWIRE_BASELINE",
    captured_at: new Date().toISOString(),
    captured_by: actor,
    window_minutes: analysis.window_minutes || Math.round(TRIPWIRE_WINDOW_MS / 60000),
    total_devices: devices.length,
    total_observations: analysis.total_observations || 0,
    device_ids: devices.map((d) => d.anonymized_id),
    devices,
    status: "operator_captured",
    notes:
      "Operator-captured backend baseline. Used for local deviation comparison only; does not identify owners or exact locations.",
  };
}

function computeTripwireBaselineDeviation(analysis, baseline = readTripwireBaseline()) {
  const devices = Array.isArray(analysis?.devices) ? analysis.devices : [];

  if (!baseline) {
    return {
      baseline_active: false,
      summary:
        "No backend baseline captured. Current product is current-window awareness only.",
      captured_at: null,
      baseline_device_count: 0,
      current_device_count: devices.length,
      count_delta: devices.length,
      new_count: 0,
      missing_count: 0,
      persistent_new_count: 0,
      new_emitters: [],
      missing_emitters: [],
      persistent_new_emitters: [],
    };
  }

  const baselineDevices = Array.isArray(baseline.devices) ? baseline.devices : [];
  const baselineIds = new Set(
    (baseline.device_ids || baselineDevices.map((d) => d.anonymized_id)).filter(Boolean)
  );
  const currentIds = new Set(devices.map((d) => d.anonymized_id).filter(Boolean));

  const newDevices = devices.filter((d) => d?.anonymized_id && !baselineIds.has(d.anonymized_id));
  const missingDevices = baselineDevices.filter(
    (d) => d?.anonymized_id && !currentIds.has(d.anonymized_id)
  );
  const persistentNewDevices = newDevices.filter(
    (d) => d.persistence_level === "Persistent"
  );

  const countDelta = devices.length - baselineIds.size;

  let summary = `Compared against backend baseline captured ${baseline.captured_at || "unknown time"}: ${newDevices.length} new emitter(s), ${missingDevices.length} missing baseline emitter(s), count delta ${countDelta}.`;
  if (!newDevices.length && !missingDevices.length && countDelta === 0) {
    summary = `No device-count or identity deviation from backend baseline captured ${baseline.captured_at || "unknown time"}.`;
  } else if (persistentNewDevices.length) {
    summary += ` ${persistentNewDevices.length} new persistent emitter(s) require human verification.`;
  }

  return {
    baseline_active: true,
    captured_at: baseline.captured_at || null,
    captured_by: baseline.captured_by || null,
    baseline_device_count: baselineIds.size,
    current_device_count: devices.length,
    count_delta: countDelta,
    new_count: newDevices.length,
    missing_count: missingDevices.length,
    persistent_new_count: persistentNewDevices.length,
    new_emitters: newDevices.slice(0, 12).map(baselineDeviceLabel),
    missing_emitters: missingDevices.slice(0, 12).map(baselineDeviceLabel),
    persistent_new_emitters: persistentNewDevices.slice(0, 12).map(baselineDeviceLabel),
    summary,
  };
}

function enrichTripwireAnalysisWithBaseline(analysis) {
  const baseline = readTripwireBaseline();
  const deviation = computeTripwireBaselineDeviation(analysis, baseline);

  return {
    ...analysis,
    baseline: baseline
      ? {
          active: true,
          captured_at: baseline.captured_at,
          captured_by: baseline.captured_by,
          total_devices: baseline.total_devices,
          total_observations: baseline.total_observations,
          window_minutes: baseline.window_minutes,
          status: baseline.status,
        }
      : { active: false },
    baseline_deviation: deviation,
  };
}

// ===========================================================================
// Analysis (preserved verbatim from original)
// ===========================================================================
function rssiProximityBand(avgRssi) {
  if (avgRssi === null || avgRssi === undefined) return "Unknown";
  if (avgRssi >= -50) return "Very Close";
  if (avgRssi >= -70) return "Nearby";
  if (avgRssi >= -85) return "Edge of Zone";
  return "Weak / Unreliable";
}

function persistenceLevel(count) {
  if (count >= 10) return "Persistent";
  if (count >= 3) return "Intermittent";
  return "Transient";
}

function confidenceForDevice(count, avgRssi) {
  if (count >= 10 && avgRssi !== null && avgRssi >= -70) return "High";
  if (count >= 3) return "Medium";
  return "Low";
}

// Bluetooth SIG-assigned company identifier for Apple Inc. (0x004C), as it
// appears over the air: little-endian, so "4C00" at the start of the hex
// manufacturer-data string.
const APPLE_COMPANY_ID_HEX = "4C00";

function appleContinuityClass(manufacturerDataHex) {
  if (!manufacturerDataHex || manufacturerDataHex.length < 6) return null;
  const companyId = manufacturerDataHex.slice(0, 4).toUpperCase();
  if (companyId !== APPLE_COMPANY_ID_HEX) return null;

  // Continuity protocol type byte (3rd byte). Reference: public
  // reverse-engineering of Apple's Continuity protocol (e.g. the
  // furiousMAC/continuity project). Only the two most consistently
  // documented type bytes are mapped here -- extend this table as you
  // verify more against your own captures.
  const typeByte = manufacturerDataHex.slice(4, 6).toUpperCase();
  if (typeByte === "02") return "Apple iBeacon-Like Device";
  if (typeByte === "07") return "Apple AirPods/Proximity-Pairing-Like Device";
  return "Apple Device (Continuity Protocol)";
}

function inferDeviceClass(obsList) {
  const names = obsList
    .map((o) => String(o.advertised_name || o.uuid || "").toLowerCase())
    .join(" ");

  // Manufacturer-data classification takes priority over name matching --
  // it's keyed on the actual company identifier broadcast in the
  // advertisement, which is present even when a device sends no name at
  // all (the common case for modern iPhones/AirPods/etc).
  for (const o of obsList) {
    const cls = appleContinuityClass(o.manufacturer_data);
    if (cls) return cls;
  }

  if (/iphone|android|galaxy|pixel|phone/.test(names))
    return "Smartphone-Like Device";
  if (/watch|fitbit|garmin/.test(names)) return "Wearable-Like Device";
  if (/airpod|buds|headphone|headset|audio|ear/.test(names))
    return "Headset/Audio-Like Device";
  if (/beacon|tile|tag|vehicle|car/.test(names))
    return "Vehicle/Beacon-Like Device";
  if (/keyboard|mouse|printer|peripheral/.test(names))
    return "Peripheral/Transient Device";
  return "Unknown BLE Device";
}

function mostCommonAdvertisedName(obsList) {
  const counts = new Map();
  for (const obs of obsList || []) {
    const name = String(
      obs.advertised_name ||
      obs.name ||
      obs.local_name ||
      obs.uuid ||
      ""
    ).trim();

    if (!name) continue;
    counts.set(name, (counts.get(name) || 0) + 1);
  }

  let best = "";
  let bestCount = 0;
  for (const [name, count] of counts.entries()) {
    if (count > bestCount) {
      best = name;
      bestCount = count;
    }
  }
  return best;
}

function mostCommonAddressType(obsList) {
  const counts = new Map();
  for (const o of obsList) {
    const t = String(o.address_type || "unknown");
    counts.set(t, (counts.get(t) || 0) + 1);
  }
  let best = "unknown";
  let bestCount = 0;
  for (const [t, c] of counts.entries()) {
    if (c > bestCount) {
      best = t;
      bestCount = c;
    }
  }
  return best;
}

function analyzeTripwireWindow(records) {
  const grouped = new Map();
  for (const obs of records) {
    if (!grouped.has(obs.anonymized_id)) grouped.set(obs.anonymized_id, []);
    grouped.get(obs.anonymized_id).push(obs);
  }

  const devices = [];
  for (const [anonymizedId, obsList] of grouped.entries()) {
    const rssiValues = obsList
      .map((o) => safeNumber(o.rssi_dbm, null))
      .filter((n) => n !== null);

    const rssiMin = rssiValues.length ? Math.min(...rssiValues) : null;
    const rssiMax = rssiValues.length ? Math.max(...rssiValues) : null;
    const rssiAvg = rssiValues.length
      ? Number(
          (rssiValues.reduce((a, b) => a + b, 0) / rssiValues.length).toFixed(1)
        )
      : null;

    const times = obsList
      .map((o) => new Date(o.received_at || o.ts).getTime())
      .filter(Number.isFinite)
      .sort((a, b) => a - b);

    const addressType = mostCommonAddressType(obsList);
    const serviceUuids = Array.from(
      new Set(obsList.flatMap((o) => o.service_uuids || []))
    ).slice(0, 10);

    const limitations = [
      "RSSI is not precise distance.",
      "Bluetooth MAC randomization may affect device continuity.",
      "Single-sensor observation cannot triangulate location.",
      "Device class is inferred from limited Bluetooth/BLE metadata.",
    ];
    if (addressType === "random_resolvable_private") {
      limitations.push(
        "Address type is a randomized resolvable private address; this physical device may reappear under a different anonymized_id after its next address rotation."
      );
    }

    devices.push({
      anonymized_id: anonymizedId,
      device_name: mostCommonAdvertisedName(obsList),
      raw_mac: obsList[0]?.raw_mac || null,
      bluetooth_id: obsList[0]?.raw_mac || null,
      device_class_estimate: inferDeviceClass(obsList),
      address_type: addressType,
      service_uuids: serviceUuids,
      observation_count: obsList.length,
      rssi_min_dbm: rssiMin,
      rssi_max_dbm: rssiMax,
      rssi_avg_dbm: rssiAvg,
      proximity_band: rssiProximityBand(rssiAvg),
      persistence_level: persistenceLevel(obsList.length),
      first_seen: times.length ? new Date(times[0]).toISOString() : null,
      last_seen: times.length
        ? new Date(times[times.length - 1]).toISOString()
        : null,
      confidence: confidenceForDevice(obsList.length, rssiAvg),
      limitations,
    });
  }

  devices.sort((a, b) => {
    const ar = a.rssi_avg_dbm ?? -999;
    const br = b.rssi_avg_dbm ?? -999;
    return br - ar;
  });

  const strongest = devices[0] || null;

  return {
    generated_at: new Date().toISOString(),
    window_minutes: Math.round(TRIPWIRE_WINDOW_MS / 60000),
    total_observations: records.length,
    total_devices: devices.length,
    persistent_devices: devices.filter((d) => d.persistence_level === "Persistent")
      .length,
    intermittent_devices: devices.filter(
      (d) => d.persistence_level === "Intermittent"
    ).length,
    transient_devices: devices.filter((d) => d.persistence_level === "Transient")
      .length,
    strongest_device: strongest
      ? {
          anonymized_id: strongest.anonymized_id,
          device_name: strongest.device_name || "",
          raw_mac: strongest.raw_mac || strongest.bluetooth_id || null,
          bluetooth_id: strongest.bluetooth_id || strongest.raw_mac || null,
          rssi_avg_dbm: strongest.rssi_avg_dbm,
          proximity_band: strongest.proximity_band,
          persistence_level: strongest.persistence_level,
          confidence: strongest.confidence,
        }
      : null,
    devices,
  };
}

// ===========================================================================
// ADDED: data-sufficiency gate
// ===========================================================================
function evaluateDataSufficiency(analysis) {
  const reasons = [];
  const total = analysis.total_observations || 0;
  if (total < MIN_OBSERVATIONS) {
    reasons.push(
      `Only ${total} observation(s) in window; minimum ${MIN_OBSERVATIONS} required.`
    );
  }
  let newest = -Infinity;
  for (const d of analysis.devices || []) {
    const t = Date.parse(d.last_seen);
    if (!Number.isNaN(t) && t > newest) newest = t;
  }
  if (newest === -Infinity) {
    reasons.push("No timestamped observations available.");
  } else if (Date.now() - newest > MAX_DATA_AGE_MS) {
    const ageMin = Math.round((Date.now() - newest) / 60000);
    reasons.push(
      `Newest observation is ${ageMin} min old; exceeds freshness limit of ${
        MAX_DATA_AGE_MS / 60000
      } min.`
    );
  }
  return { ok: reasons.length === 0, reasons };
}


function stripRawBluetoothIdentifiers(value) {
  if (Array.isArray(value)) return value.map(stripRawBluetoothIdentifiers);

  if (value && typeof value === "object") {
    const blocked = new Set([
      "raw_mac",
      "bluetooth_id",
      "mac",
      "address",
      "addr",
      "observed_address",
    ]);

    const out = {};
    for (const [key, val] of Object.entries(value)) {
      if (blocked.has(key)) continue;
      out[key] = stripRawBluetoothIdentifiers(val);
    }
    return out;
  }

  return value;
}

function safeEmitterDescriptor(d) {
  const name = String(d?.device_name || d?.advertised_name || "").trim();
  const anon = String(d?.anonymized_id || "emitter");
  const cls = String(d?.device_class_estimate || "BLE emitter");
  const persistence = String(d?.persistence_level || "unknown persistence");
  const proximity = String(d?.proximity_band || "unknown proximity");
  const rssi = d?.rssi_avg_dbm ?? "n/a";

  const label = name ? `${name} (${anon})` : anon;
  return `${label}: ${cls}; ${persistence}; ${proximity}; avg RSSI ${rssi} dBm`;
}


function baselineDeviationText(analysis = {}) {
  const d = analysis?.baseline_deviation;
  if (!d || !d.baseline_active) {
    return "No backend baseline captured. Current product is current-window awareness only.";
  }
  return d.summary || `Compared against backend baseline: ${d.new_count || 0} new emitter(s), ${d.missing_count || 0} missing baseline emitter(s), count delta ${d.count_delta || 0}.`;
}

function buildDecisionSupportFields(analysis = {}, opts = {}) {
  const devices = Array.isArray(analysis.devices) ? analysis.devices : [];
  const total = analysis.total_devices || devices.length || 0;
  const obs = analysis.total_observations || 0;
  const windowMin = analysis.window_minutes || "current";
  const persistentCount = analysis.persistent_devices || devices.filter(
    (d) => d.persistence_level === "Persistent"
  ).length;
  const intermittentCount = analysis.intermittent_devices || devices.filter(
    (d) => d.persistence_level === "Intermittent"
  ).length;
  const transientCount = analysis.transient_devices || devices.filter(
    (d) => d.persistence_level === "Transient"
  ).length;

  const persistentDevices = devices.filter((d) => d.persistence_level === "Persistent");
  const veryCloseDevices = devices.filter((d) => d.proximity_band === "Very Close");
  const namedOrTypedDevices = devices.filter((d) => {
    const cls = String(d.device_class_estimate || "");
    return d.device_name || (cls && !/unknown/i.test(cls));
  });
  const unknownDevices = devices.filter((d) => {
    const cls = String(d.device_class_estimate || "");
    return !d.device_name && (!cls || /unknown/i.test(cls));
  });
  const unknownPersistent = persistentDevices.filter((d) => {
    const cls = String(d.device_class_estimate || "");
    return !d.device_name && (!cls || /unknown/i.test(cls));
  });

  let inferredAlert = opts.alert || "Green";
  if (!opts.insufficient) {
    if ((persistentCount >= 3 && veryCloseDevices.length >= 1) || unknownPersistent.length >= 2) {
      inferredAlert = "Red";
    } else if (persistentCount >= 1 || veryCloseDevices.length >= 1 || unknownDevices.length >= 1) {
      inferredAlert = "Yellow";
    }
  }

  let operatorDecision = "Monitor";
  if (opts.insufficient) operatorDecision = "Monitor";
  else if (inferredAlert === "Red") operatorDecision = "No-Go";
  else if (inferredAlert === "Yellow") operatorDecision = "Verify First";
  else operatorDecision = "Monitor";

  const bottomLine = opts.insufficient
    ? `Assessment withheld. Available BLE data is insufficient for a confident operator product: ${(opts.reasons || []).join(" ")}`
    : `${inferredAlert} BLE posture. ${total} emitter(s) observed across ${obs} observation(s) in the last ${windowMin} min; ${persistentCount} persistent, ${intermittentCount} intermittent, ${transientCount} transient. ${veryCloseDevices.length ? `${veryCloseDevices.length} very-close emitter(s) require verification.` : "No very-close emitter detected."}`;

  const recommendedNextAction =
    operatorDecision === "No-Go"
      ? "Pause sensitive activity until persistent/very-close or unknown emitters are verified by a human operator."
      : operatorDecision === "Verify First"
        ? "Verify persistent and unknown emitters against the expected zone baseline before sensitive activity."
        : "Continue passive monitoring and re-check posture before sensitive activity.";

  return {
    bottom_line: bottomLine,
    operator_decision: operatorDecision,
    what_changed: opts.insufficient
      ? [
          "The system withheld assessment because the observation set did not meet the data-sufficiency gate.",
          ...(opts.reasons || []),
        ]
      : [
          `Current window contains ${total} distinct BLE emitter(s) across ${obs} observation(s).`,
          `${persistentCount} persistent, ${intermittentCount} intermittent, ${transientCount} transient emitter(s) observed.`,
          veryCloseDevices.length
            ? `${veryCloseDevices.length} very-close emitter(s) observed.`
            : "No very-close emitter observed.",
          analysis?.baseline_deviation?.baseline_active
            ? `Baseline comparison: ${analysis.baseline_deviation.new_count} new emitter(s), ${analysis.baseline_deviation.missing_count} missing baseline emitter(s), count delta ${analysis.baseline_deviation.count_delta}.`
            : "No backend baseline captured; deviation is assessed against the current observation window only.",
        ],
    known_emitters: namedOrTypedDevices.length
      ? namedOrTypedDevices.slice(0, 8).map(safeEmitterDescriptor)
      : ["No known or typed emitters identified from advertised metadata in this window."],
    unknown_emitters: unknownDevices.length
      ? unknownDevices.slice(0, 8).map(safeEmitterDescriptor)
      : ["No unknown emitters requiring classification were identified in this window."],
    persistent_emitters: persistentDevices.length
      ? persistentDevices.slice(0, 8).map(safeEmitterDescriptor)
      : ["No persistent emitters observed in this window."],
    baseline_deviation: baselineDeviationText(analysis),
    key_questions: [
      {
        question: "Q1: Are unexpected devices present in the monitored zone?",
        assessment: unknownDevices.length
          ? `${unknownDevices.length} unknown BLE emitter(s) observed; authorization cannot be determined from passive BLE alone.`
          : "No unknown BLE emitter requiring classification was identified from the current analysis.",
        confidence: obs >= 10 ? "Medium" : "Low",
      },
      {
        question: "Q2: Are persistent emitters present that are not part of the captured baseline?",
        assessment: persistentDevices.length
          ? `${persistentDevices.length} persistent emitter(s) observed. Baseline comparison is unavailable until backend baseline is implemented.`
          : "No persistent emitters observed.",
        confidence: obs >= 10 ? "Medium" : "Low",
      },
      {
        question: "Q3: Is there high-proximity BLE activity near the sensor?",
        assessment: veryCloseDevices.length
          ? `${veryCloseDevices.length} very-close emitter(s) observed; human verification recommended.`
          : "No very-close BLE emitter observed.",
        confidence: obs >= 10 ? "Medium" : "Low",
      },
    ],
    intelligence_gaps: [
      "Passive BLE cannot identify device owner or user.",
      "Single-sensor RSSI cannot provide precise location or triangulation.",
      "Bluetooth address randomization may affect continuity.",
      "No approved backend zone baseline is available yet.",
      "Authorization status requires a local device registry or human verification.",
    ],
    recommended_next_action: recommendedNextAction,
  };
}

function insufficientDataProduct(reasons) {
  const decisionFields = buildDecisionSupportFields(
    { total_devices: 0, total_observations: 0, persistent_devices: 0, devices: [] },
    { insufficient: true, reasons, alert: "Green" }
  );

  return {
    title: "Bluetooth / BLE Emissions Awareness Report",
    ...decisionFields,
    executive_summary:
      "INSUFFICIENT DATA -- no assessment generated. The observation set is too thin or too stale to support a confident product. " +
      reasons.join(" "),
    key_terrain_rf_terrain_assessment: "Not assessed (insufficient data).",
    exposure_risk: {
      level: "Low",
      rationale:
        "Risk not assessed due to insufficient data. Absence of evidence is not evidence of absence.",
    },
    operator_takeaways: [
      "No reliable assessment available for this window.",
      "Collect more observations or reduce the gap since last collection before relying on output.",
    ],
    recommended_defensive_actions: [
      "Continue passive monitoring until the data-sufficiency threshold is met.",
      "Verify the sensor is enabled and reporting.",
    ],
    decision_support: {
      alert_level: "Green",
      recommended_operator_focus: "No action indicated; data insufficient.",
      human_decision_required: true,
    },
    confidence: {
      level: "Low",
      rationale: "Below data-sufficiency threshold; " + reasons.join(" "),
    },
    limitations: [
      "Insufficient or stale data.",
      "RSSI is not precise distance.",
      "Single-sensor observation cannot triangulate location.",
    ],
  };
}

// Deterministic report builder (the only report path in this app).
function deterministicFallbackProduct(analysis, note) {
  const persistent = analysis.persistent_devices || 0;
  const strongest = analysis.strongest_device || null;
  const close =
    strongest && strongest.rssi_avg_dbm != null && strongest.rssi_avg_dbm >= -50;
  let level = "Low";
  let alert = "Green";
  if (persistent >= 1 || close) {
    level = "Moderate";
    alert = "Yellow";
  }
  if (persistent >= 3 && close) {
    level = "High";
    alert = "Red";
  }
  const decisionFields = buildDecisionSupportFields(analysis, { alert, note });

  return {
    title: "Bluetooth / BLE Emissions Awareness Report",
    ...decisionFields,
    executive_summary:
      `Deterministic fallback (${note}). In the last ${analysis.window_minutes} min, ` +
      `${analysis.total_devices} distinct BLE emitter(s) across ${analysis.total_observations} observation(s): ` +
      `${persistent} persistent, ${analysis.intermittent_devices} intermittent, ${analysis.transient_devices} transient.`,
    key_terrain_rf_terrain_assessment: strongest
      ? `Strongest emitter ${strongest.anonymized_id} ~${strongest.rssi_avg_dbm} dBm (${strongest.proximity_band}).`
      : "No emitters with usable RSSI in the current window.",
    exposure_risk: {
      level,
      rationale: `${persistent} persistent emitter(s); strongest band ${
        strongest ? strongest.proximity_band : "n/a"
      }. RSSI is not precise distance.`,
    },
    operator_takeaways: [
      `${analysis.total_devices} distinct BLE emitter(s) over ${analysis.window_minutes} min.`,
      persistent >= 1
        ? `${persistent} emitter(s) persistent -- possible sustained presence.`
        : "No persistent emitters in window.",
    ],
    recommended_defensive_actions: [
      "Confirm whether observed BLE activity is expected for this zone and period.",
      "If emissions exceed posture, advise personnel to disable non-essential Bluetooth (human-approved).",
      "Continue passive monitoring; re-baseline during a known-quiet period.",
    ],
    decision_support: {
      alert_level: alert,
      recommended_operator_focus:
        persistent >= 1
          ? "Review persistent emitters against expected friendly baseline."
          : "Maintain passive awareness; no action indicated.",
      human_decision_required: true,
    },
    confidence: {
      level: analysis.total_observations >= 10 ? "Medium" : "Low",
      rationale: "Generated locally without model assistance.",
    },
    limitations: [
      "RSSI is not precise distance.",
      "Bluetooth MAC randomization may affect continuity.",
      "Single-sensor observation cannot triangulate location.",
      "Device class is inferred from limited metadata.",
    ],
  };
}

// ===========================================================================
// ADDED: HMAC-chained audit log (tamper-evident when AUDIT_SECRET is private)
// ===========================================================================
function lastAuditHash() {
  try {
    if (!fs.existsSync(TRIPWIRE_AUDIT_FILE)) return "GENESIS";
    const lines = fs
      .readFileSync(TRIPWIRE_AUDIT_FILE, "utf8")
      .split("\n")
      .filter(Boolean);
    if (!lines.length) return "GENESIS";
    return JSON.parse(lines[lines.length - 1]).entry_hash || "GENESIS";
  } catch {
    return "GENESIS";
  }
}

function appendAudit(event) {
  try {
    ensureTripwireDataDir();
    const entry = { ts: new Date().toISOString(), prev_hash: lastAuditHash(), ...event };
    const entry_hash = crypto
      .createHmac("sha256", TRIPWIRE_AUDIT_SECRET)
      .update(JSON.stringify(entry))
      .digest("hex");
    fs.appendFileSync(
      TRIPWIRE_AUDIT_FILE,
      JSON.stringify({ ...entry, entry_hash }) + "\n"
    );
    return entry_hash;
  } catch (e) {
    console.warn(`[BLE-TRIPWIRE] audit append failed: ${e.message}`);
    return null;
  }
}

function verifyAuditChain() {
  if (!fs.existsSync(TRIPWIRE_AUDIT_FILE))
    return { ok: true, length: 0, broken_at: null };
  let lines;
  try {
    lines = fs
      .readFileSync(TRIPWIRE_AUDIT_FILE, "utf8")
      .split("\n")
      .filter(Boolean);
  } catch (e) {
    return { ok: false, length: 0, broken_at: 0, error: e.message };
  }
  let prev = "GENESIS";
  for (let i = 0; i < lines.length; i++) {
    let rec;
    try {
      rec = JSON.parse(lines[i]);
    } catch {
      return { ok: false, length: lines.length, broken_at: i, error: "unparseable line" };
    }
    if (rec.prev_hash !== prev)
      return { ok: false, length: lines.length, broken_at: i, error: "prev_hash mismatch" };
    const { entry_hash, ...rest } = rec;
    const recomputed = crypto
      .createHmac("sha256", TRIPWIRE_AUDIT_SECRET)
      .update(JSON.stringify(rest))
      .digest("hex");
    if (recomputed !== entry_hash)
      return {
        ok: false,
        length: lines.length,
        broken_at: i,
        error: "entry_hash mismatch (tampered)",
      };
    prev = entry_hash;
  }
  return { ok: true, length: lines.length, broken_at: null };
}

function actorOf(req) {
  // Trust ONLY the server-authenticated identity (server.js basicAuthMiddleware
  // sets req.user after bcrypt verification). Client-supplied headers/body are
  // deliberately ignored so the audit chain's actor cannot be spoofed.
  // `claimed_actor` is captured separately for forensic context, never as truth.
  return req?.user?.name || req?.user?.id || "unauthenticated";
}

function claimedActorOf(req) {
  // Untrusted, for forensics only. May differ from actorOf() if a caller lies.
  return req?.headers?.["x-actor"] || req?.body?.actor || null;
}

// ===========================================================================
// Routes
// ===========================================================================
// ===========================================================================
// ADDED: passive RF tripwire — unknown-emitter detection + alert state machine
// Deterministic (no model). States: KNOWN / WATCH / ALERT / CLOSING.
//   KNOWN   - emitter is in the captured baseline (friendly/expected)
//   WATCH   - unknown but distant or unconfirmed (logged, no alarm)
//   ALERT   - unknown, at/inside zone RSSI, confirmed across >= CONFIRM sweeps
//   CLOSING - unknown whose RSSI is trending up (approaching) — highest priority
// ===========================================================================
const TRIPWIRE = {
  ZONE_DBM: Number(process.env.BLE_TRIPWIRE_ZONE_DBM || -78),
  CONFIRM_SWEEPS: Number(process.env.BLE_TRIPWIRE_CONFIRM_SWEEPS || 2),
  APPROACH_DB: Number(process.env.BLE_TRIPWIRE_APPROACH_DB || 4),
  WINDOW_MS:
    Number(process.env.BLE_TRIPWIRE_TRIPWIRE_WINDOW_SEC || 120) * 1000,
  MIN_TREND_SAMPLES: 4,
};

// Runtime-adjustable sensitivity, persisted so slider changes survive app
// restarts. Persisted values override the env/default values above.
const TRIPWIRE_CONFIG_FILE = path.join(
  process.env.BLE_TRIPWIRE_DATA_DIR || path.join(PROJECT_ROOT, "data", "tripwire"),
  "config.json"
);
const TRIPWIRE_CONFIG_LIMITS = {
  ZONE_DBM: { min: -95, max: -45 },
  CONFIRM_SWEEPS: { min: 1, max: 6 },
  APPROACH_DB: { min: 2, max: 12 },
};
function loadTripwireConfig() {
  try {
    if (!fs.existsSync(TRIPWIRE_CONFIG_FILE)) return;
    const c = JSON.parse(fs.readFileSync(TRIPWIRE_CONFIG_FILE, "utf8"));
    for (const k of Object.keys(TRIPWIRE_CONFIG_LIMITS)) {
      const v = Number(c[k]);
      const lim = TRIPWIRE_CONFIG_LIMITS[k];
      if (Number.isFinite(v) && v >= lim.min && v <= lim.max) TRIPWIRE[k] = v;
    }
  } catch (e) {
    console.warn(`[BLE-TRIPWIRE] config load failed: ${e.message}`);
  }
}
function saveTripwireConfig() {
  try {
    ensureTripwireDataDir();
    const out = {};
    for (const k of Object.keys(TRIPWIRE_CONFIG_LIMITS)) out[k] = TRIPWIRE[k];
    fs.writeFileSync(TRIPWIRE_CONFIG_FILE, JSON.stringify(out, null, 2));
  } catch (e) {
    console.warn(`[BLE-TRIPWIRE] config save failed: ${e.message}`);
  }
}
loadTripwireConfig();

function _twMean(a) { return a.length ? a.reduce((x, y) => x + y, 0) / a.length : null; }

// Persistent return/visit tracking. A "visit" ends when an id is unseen for
// more than RETURN_GAP_MS; the next sighting starts a new visit and bumps the
// count. Kept in memory (resets on process restart, which is fine — it's a
// session-scoped "how many times has this shown up" hint, not an audit record).
const _tripwireReturns = new Map(); // id -> { count, lastSeenMs }
const RETURN_GAP_MS = 90 * 1000;
function _tripwireTrackReturns(id, obs) {
  const lastMs = obs[obs.length - 1].t;
  const firstMs = obs[0].t;
  const rec = _tripwireReturns.get(id);
  if (!rec) {
    _tripwireReturns.set(id, { count: 1, lastSeenMs: lastMs });
    return 1;
  }
  // If there was a long gap between the last time we saw it and this window's
  // first observation, count it as a new visit.
  if (firstMs - rec.lastSeenMs > RETURN_GAP_MS) rec.count += 1;
  rec.lastSeenMs = lastMs;
  return rec.count;
}

function computeThreats(now = Date.now()) {
  const baseline = readTripwireBaseline();
  const baselineIds = new Set(
    (baseline &&
      (baseline.device_ids ||
        (baseline.devices || []).map((d) => d.anonymized_id))) || []
  );
  const records = readRecentTripwireObservations(TRIPWIRE.WINDOW_MS);

  const grouped = new Map();
  for (const o of records) {
    const id = o.anonymized_id;
    if (!id) continue;
    const t = new Date(o.received_at || o.ts).getTime();
    if (!Number.isFinite(t)) continue;
    if (!grouped.has(id)) grouped.set(id, []);
    grouped.get(id).push({ t, rssi: Number(o.rssi_dbm), sensor: o.sensor_id });
  }

  const threats = [];
  const names = readTripwireNames();
  for (const [id, obs] of grouped.entries()) {
    obs.sort((a, b) => a.t - b.t);
    const rssis = obs.map((o) => o.rssi).filter(Number.isFinite);
    if (!rssis.length) continue;

    const sweeps = obs.length;
    const rssiMax = Math.max(...rssis);
    const rssiLast = obs[obs.length - 1].rssi;
    const sensors = Array.from(new Set(obs.map((o) => o.sensor).filter(Boolean)));
    const known = baselineIds.has(id);

    let rising = false, trendDb = 0;
    if (rssis.length >= TRIPWIRE.MIN_TREND_SAMPLES) {
      const half = Math.floor(rssis.length / 2);
      const first = _twMean(rssis.slice(0, half));
      const last = _twMean(rssis.slice(half));
      trendDb = Number((last - first).toFixed(1));
      rising = last - first >= TRIPWIRE.APPROACH_DB;
    }
    const confirmed = sweeps >= TRIPWIRE.CONFIRM_SWEEPS;
    const inZone = rssiMax >= TRIPWIRE.ZONE_DBM;

    let state;
    if (known) state = "KNOWN";
    else if (rising && confirmed) state = "CLOSING";
    else if (inZone && confirmed) state = "ALERT";
    else state = "WATCH";

    // Dwell = how long this id has been present in the current window.
    const dwellSec = Math.round((obs[obs.length - 1].t - obs[0].t) / 1000);
    // Return count = number of distinct visits (gaps > 90s split a visit),
    // tracked persistently so it survives beyond the sliding window.
    const returnCount = _tripwireTrackReturns(id, obs);

    threats.push({
      id,
      name: names[id] || "",
      state, known, sweeps,
      rssi_max_dbm: rssiMax, rssi_last_dbm: rssiLast,
      trend_db: trendDb, rising, in_zone: inZone,
      proximity_band: rssiProximityBand(rssiMax),
      sensors,
      dwell_sec: dwellSec,
      return_count: returnCount,
      first_seen: new Date(obs[0].t).toISOString(),
      last_seen: new Date(obs[obs.length - 1].t).toISOString(),
    });
  }

  const rank = { CLOSING: 0, ALERT: 1, WATCH: 2, KNOWN: 3 };
  threats.sort((a, b) => rank[a.state] - rank[b.state] || b.rssi_max_dbm - a.rssi_max_dbm);

  const unknowns = threats.filter((t) => !t.known);
  return {
    generated_at: new Date(now).toISOString(),
    baseline_active: !!baseline,
    zone_dbm: TRIPWIRE.ZONE_DBM,
    confirm_sweeps: TRIPWIRE.CONFIRM_SWEEPS,
    approach_db: TRIPWIRE.APPROACH_DB,
    window_sec: Math.round(TRIPWIRE.WINDOW_MS / 1000),
    counts: {
      closing: unknowns.filter((t) => t.state === "CLOSING").length,
      alert: unknowns.filter((t) => t.state === "ALERT").length,
      watch: unknowns.filter((t) => t.state === "WATCH").length,
      known: threats.filter((t) => t.known).length,
    },
    threats,
  };
}

const _tripwireLastState = new Map();
function auditThreatTransitions(threats) {
  const seen = new Set();
  for (const th of threats) {
    seen.add(th.id);
    const prev = _tripwireLastState.get(th.id) || "NONE";
    if (th.state !== prev && (th.state === "ALERT" || th.state === "CLOSING")) {
      appendAudit({
        event: "tripwire_alert",
        anonymized_id: th.id, state: th.state, prev_state: prev,
        rssi_max_dbm: th.rssi_max_dbm, sweeps: th.sweeps,
        rising: th.rising, sensors: th.sensors,
      });
    }
    _tripwireLastState.set(th.id, th.state);
  }
  for (const id of Array.from(_tripwireLastState.keys())) {
    if (!seen.has(id)) {
      const prev = _tripwireLastState.get(id);
      if (prev === "ALERT" || prev === "CLOSING") {
        appendAudit({ event: "tripwire_clear", anonymized_id: id, prev_state: prev });
      }
      _tripwireLastState.delete(id);
    }
  }
}

export function installTripwire(app) {
  ensureTripwireDataDir();

  // INGEST (auth-exempt path; preserved response shape)
  app.post("/api/sensors/ble-tripwire", (req, res) => {
    if (!tripwireEnabled) {
      return res.json({ ok: true, enabled: false, ignored: true });
    }

    const devices = req.body?.devices;
    if (!Array.isArray(devices)) {
      return res.status(400).json({
        ok: false,
        error: "Expected JSON body: { devices: [{ mac, rssi, uuid }] }",
      });
    }

    const now = new Date().toISOString();
    const newDetections = [];
    const normalized = [];

    for (const device of devices) {
      const obs = normalizeTripwireDevice(device, now);
      if (!obs.raw_mac || obs.raw_mac === "UNKNOWN") continue;

      appendTripwireObservation(obs);
      normalized.push({
        anonymized_id: obs.anonymized_id,
        rssi_dbm: obs.rssi_dbm,
        uuid: obs.uuid,
        zone: obs.zone,
        sensor_id: obs.sensor_id,
        timestamp: obs.ts,
      });

      if (!tripwireKnownDevices.has(obs.raw_mac)) {
        tripwireKnownDevices.add(obs.raw_mac);
        newDetections.push({
          anonymized_id: obs.anonymized_id,
          rssi: obs.rssi_dbm,
          uuid: obs.uuid,
          zone: obs.zone,
          timestamp: now,
        });
        console.log(
          `[BLE-TRIPWIRE] NEW DEVICE DETECTED: ${obs.anonymized_id} (RSSI: ${obs.rssi_dbm}) UUID/NAME: ${obs.uuid}`
        );
      }
    }

    const recent = readRecentTripwireObservations();
    const analysis = enrichTripwireAnalysisWithBaseline(analyzeTripwireWindow(recent));

    res.json({
      ok: true,
      enabled: true,
      received: devices.length,
      stored: normalized.length,
      newDetections: newDetections.length,
      detections: newDetections,
      analysis_summary: {
        window_minutes: analysis.window_minutes,
        total_devices: analysis.total_devices,
        total_observations: analysis.total_observations,
        persistent_devices: analysis.persistent_devices,
        intermittent_devices: analysis.intermittent_devices,
        transient_devices: analysis.transient_devices,
        strongest_device: analysis.strongest_device,
      },
    });
  });

  // STATUS (preserved shape; frontend reads .enabled)
  app.get("/api/sensors/ble-tripwire/status", (_req, res) => {
    const arm = readTripwireArm();
    res.json({
      enabled: tripwireEnabled,
      knownDevices: tripwireKnownDevices.size,
      dataFile: TRIPWIRE_OBS_FILE,
      latestIntelFile: TRIPWIRE_INTEL_FILE,
      windowMinutes: Math.round(TRIPWIRE_WINDOW_MS / 60000),
      model: "deterministic (no model — on-device)",
      armed: arm.armed,
      schedule: arm.schedule,
      notify_active: tripwireNotifyActive(arm),
      nodes: nodesFromObservations(),
    });
  });

  // TOGGLE (preserved shape; + audit entry)
  app.post("/api/sensors/ble-tripwire/toggle", (req, res) => {
    const want = req.body?.enabled;
    tripwireEnabled = typeof want === "boolean" ? want : !tripwireEnabled;
    console.log(
      `[BLE-TRIPWIRE] ${tripwireEnabled ? "ENABLED" : "DISABLED"} via UI`
    );
    appendAudit({
      event: "toggle",
      enabled: tripwireEnabled,
      actor: actorOf(req),
      claimed_actor: claimedActorOf(req),
    });
    res.json({
      enabled: tripwireEnabled,
      knownDevices: tripwireKnownDevices.size,
    });
  });

  // REPORT (returns the last generated report; preserved shape)
  app.get("/api/sensors/ble-tripwire/intel", (_req, res) => {
    try {
      const records = readRecentTripwireObservations();
      const analysis = enrichTripwireAnalysisWithBaseline(analyzeTripwireWindow(records));

      let latestProduct = null;
      if (fs.existsSync(TRIPWIRE_INTEL_FILE)) {
        try {
          latestProduct = JSON.parse(
            fs.readFileSync(TRIPWIRE_INTEL_FILE, "utf8")
          );
        } catch {
          latestProduct = null;
        }
      }

      res.json({
        ok: true,
        type: "TRIPWIRE_ANALYSIS",
        generated_at: new Date().toISOString(),
        analysis,
        latest_product: latestProduct,
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // BASELINE: capture current window as backend persistent baseline
  app.post("/api/sensors/ble-tripwire/baseline/capture", (req, res) => {
    try {
      const records = readRecentTripwireObservations();
      const analysis = analyzeTripwireWindow(records);
      const baseline = writeTripwireBaseline(
        buildTripwireBaseline(analysis, actorOf(req))
      );
      const enriched = enrichTripwireAnalysisWithBaseline(analysis);

      const audit_hash = appendAudit({
        event: "baseline_capture",
        actor: actorOf(req),
        claimed_actor: claimedActorOf(req),
        baseline_devices: baseline.total_devices,
        total_observations: baseline.total_observations,
      });

      res.json({
        ok: true,
        baseline,
        baseline_deviation: enriched.baseline_deviation,
        audit_hash,
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // BASELINE: read backend persistent baseline and current deviation
  app.get("/api/sensors/ble-tripwire/baseline", (_req, res) => {
    try {
      const baseline = readTripwireBaseline();
      const records = readRecentTripwireObservations();
      const analysis = analyzeTripwireWindow(records);
      const baseline_deviation = computeTripwireBaselineDeviation(analysis, baseline);

      res.json({
        ok: true,
        baseline,
        baseline_deviation,
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // BASELINE: clear backend persistent baseline
  app.delete("/api/sensors/ble-tripwire/baseline", (req, res) => {
    try {
      deleteTripwireBaseline();

      const audit_hash = appendAudit({
        event: "baseline_clear",
        actor: actorOf(req),
        claimed_actor: claimedActorOf(req),
      });

      res.json({ ok: true, baseline: null, audit_hash });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // PROCESS (gate -> deterministic product -> latest_report.json -> audit)
  app.post("/api/sensors/ble-tripwire/process", async (req, res) => {
    try {
      const records = readRecentTripwireObservations();
      const analysis = enrichTripwireAnalysisWithBaseline(analyzeTripwireWindow(records));

      // DATA-SUFFICIENCY GATE
      const gate = evaluateDataSufficiency(analysis);
      let product;
      let source;
      if (!gate.ok) {
        product = insufficientDataProduct(gate.reasons);
        source = "data_sufficiency_gate";
      } else {
        // The report is fully deterministic (signal-posture scoring, tripwire
        // state machine, decision support). No AI/model layer in this app.
        product = deterministicFallbackProduct(
          analysis,
          "deterministic product (no model layer in this app)"
        );
        source = "deterministic";
      }

      const finalProduct = {
        ok: true,
        type: "BLE_TRIPWIRE_REPORT",
        generated_at: new Date().toISOString(),
        source,
        model: null,
        data_sufficiency: gate,
        analysis,
        product,
        safety_boundary: {
          mode: "defensive_passive_local_only",
          no_pairing: true,
          no_exploitation: true,
          no_jamming: true,
          no_targeting: true,
          human_decision_required: true,
        },
      };

      ensureTripwireDataDir();
      fs.writeFileSync(
        TRIPWIRE_INTEL_FILE,
        JSON.stringify(finalProduct, null, 2),
        "utf8"
      );

      const audit_hash = appendAudit({
        event: "process",
        source,
        model: finalProduct.model,
        total_observations: analysis.total_observations,
        total_devices: analysis.total_devices,
        exposure_level: product.exposure_risk?.level,
        alert_level: product.decision_support?.alert_level,
        human_decision_required: true,
        actor: actorOf(req),
        claimed_actor: claimedActorOf(req),
      });

      res.json({ audit_hash, ...finalProduct });
    } catch (err) {
      appendAudit({
        event: "process_error",
        error: String(err.message || err),
        actor: actorOf(req),
        claimed_actor: claimedActorOf(req),
      });
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // AUDIT VERIFY (read-only integrity check)
  // AUDIT LOG (read) — most-recent-first list of audit entries for the
  // history view. The chain itself stays append-only on disk.
  app.get("/api/sensors/ble-tripwire/audit", (req, res) => {
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
      let entries = [];
      if (fs.existsSync(TRIPWIRE_AUDIT_FILE)) {
        entries = fs
          .readFileSync(TRIPWIRE_AUDIT_FILE, "utf8")
          .split("\n")
          .filter(Boolean)
          .slice(-limit)
          .map((l) => { try { return JSON.parse(l); } catch { return null; } })
          .filter(Boolean)
          .reverse();
      }
      res.json({ ok: true, count: entries.length, entries });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // CONFIG (runtime sensitivity) — read + update, persisted across restarts.
  app.get("/api/sensors/ble-tripwire/config", (_req, res) => {
    res.json({
      ok: true,
      config: {
        zone_dbm: TRIPWIRE.ZONE_DBM,
        confirm_sweeps: TRIPWIRE.CONFIRM_SWEEPS,
        approach_db: TRIPWIRE.APPROACH_DB,
      },
      limits: {
        zone_dbm: TRIPWIRE_CONFIG_LIMITS.ZONE_DBM,
        confirm_sweeps: TRIPWIRE_CONFIG_LIMITS.CONFIRM_SWEEPS,
        approach_db: TRIPWIRE_CONFIG_LIMITS.APPROACH_DB,
      },
    });
  });

  app.post("/api/sensors/ble-tripwire/config", (req, res) => {
    try {
      const body = req.body || {};
      const map = {
        zone_dbm: "ZONE_DBM",
        confirm_sweeps: "CONFIRM_SWEEPS",
        approach_db: "APPROACH_DB",
      };
      const applied = {};
      for (const [key, prop] of Object.entries(map)) {
        if (body[key] === undefined) continue;
        const v = Number(body[key]);
        const lim = TRIPWIRE_CONFIG_LIMITS[prop];
        if (!Number.isFinite(v) || v < lim.min || v > lim.max) {
          return res.status(400).json({
            ok: false,
            error: `${key} out of range (${lim.min}..${lim.max})`,
          });
        }
        TRIPWIRE[prop] = prop === "ZONE_DBM" ? Math.round(v) : Math.round(v);
        applied[key] = TRIPWIRE[prop];
      }
      if (Object.keys(applied).length) {
        saveTripwireConfig();
        // NOTE: sensitivity tweaks are deliberately NOT written to the audit
        // chain. The chain is for security events (alerts, baseline changes,
        // arm/disarm) — logging every slider adjustment buried those under
        // noise. Config is still persisted to config.json above.
      }
      res.json({
        ok: true,
        config: {
          zone_dbm: TRIPWIRE.ZONE_DBM,
          confirm_sweeps: TRIPWIRE.CONFIRM_SWEEPS,
          approach_db: TRIPWIRE.APPROACH_DB,
        },
      });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // BASELINE: remove a single device (un-trust one emitter without wiping
  // the whole baseline).
  app.delete("/api/sensors/ble-tripwire/baseline/device/:id", (req, res) => {
    try {
      const id = String(req.params.id || "").trim();
      if (!id) return res.status(400).json({ ok: false, error: "missing device id" });
      const baseline = readTripwireBaseline();
      if (!baseline) return res.status(404).json({ ok: false, error: "no baseline captured" });

      const before =
        (baseline.device_ids && baseline.device_ids.length) ||
        (baseline.devices && baseline.devices.length) || 0;
      if (Array.isArray(baseline.devices))
        baseline.devices = baseline.devices.filter((d) => d.anonymized_id !== id);
      if (Array.isArray(baseline.device_ids))
        baseline.device_ids = baseline.device_ids.filter((x) => x !== id);
      const after =
        (baseline.device_ids && baseline.device_ids.length) ||
        (baseline.devices && baseline.devices.length) || 0;
      if (after === before)
        return res.status(404).json({ ok: false, error: "device not in baseline" });

      baseline.total_devices = after;
      writeTripwireBaseline(baseline);
      appendAudit({ event: "baseline_device_removed", actor: actorOf(req), anonymized_id: id });
      res.json({ ok: true, removed: id, remaining: after });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // NAMES: custom labels for anonymized ids (readable UI). Naming is just a
  // label — it does NOT trust/baseline the device (separate deliberate action).
  app.get("/api/sensors/ble-tripwire/names", (_req, res) => {
    res.json({ ok: true, names: readTripwireNames() });
  });
  app.post("/api/sensors/ble-tripwire/names", (req, res) => {
    try {
      const { id, name } = req.body || {};
      if (!id) return res.status(400).json({ ok: false, error: "missing id" });
      const map = setTripwireName(String(id), name);
      res.json({ ok: true, names: map });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // ARM: arm/disarm gates NOTIFICATIONS only — sensing + history keep running.
  // Optional daily schedule window. Both transitions are audit-logged (they're
  // real security events, unlike sensitivity tweaks).
  app.get("/api/sensors/ble-tripwire/arm", (_req, res) => {
    const state = readTripwireArm();
    res.json({ ok: true, ...state, notify_active: tripwireNotifyActive(state) });
  });
  app.post("/api/sensors/ble-tripwire/arm", (req, res) => {
    try {
      const cur = readTripwireArm();
      const b = req.body || {};
      const next = {
        armed: typeof b.armed === "boolean" ? b.armed : cur.armed,
        schedule: {
          enabled: typeof b.schedule?.enabled === "boolean" ? b.schedule.enabled : cur.schedule.enabled,
          start: b.schedule?.start || cur.schedule.start,
          end: b.schedule?.end || cur.schedule.end,
        },
      };
      writeTripwireArm(next);
      if (next.armed !== cur.armed) {
        appendAudit({ event: next.armed ? "armed" : "disarmed", actor: actorOf(req) });
      }
      res.json({ ok: true, ...next, notify_active: tripwireNotifyActive(next) });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  // EXPORT: dump the audit chain as a downloadable file (text or CSV) so an
  // incident record can leave the phone. Read-only; the on-disk chain is
  // untouched.
  app.get("/api/sensors/ble-tripwire/audit/export", (req, res) => {
    try {
      const fmt = (req.query.format === "csv") ? "csv" : "txt";
      let entries = [];
      if (fs.existsSync(TRIPWIRE_AUDIT_FILE)) {
        entries = fs.readFileSync(TRIPWIRE_AUDIT_FILE, "utf8")
          .split("\n").filter(Boolean)
          .map((l) => { try { return JSON.parse(l); } catch { return null; } })
          .filter(Boolean);
      }
      if (fmt === "csv") {
        const rows = ["timestamp,event,anonymized_id,state,detail"];
        for (const e of entries) {
          const detail = JSON.stringify(e.applied || e.sensors || "").replace(/"/g, "'");
          rows.push([e.ts, e.event, e.anonymized_id || "", e.state || "", `"${detail}"`].join(","));
        }
        res.setHeader("Content-Type", "text/csv");
        res.setHeader("Content-Disposition", 'attachment; filename="ble-tripwire-log.csv"');
        return res.send(rows.join("\n"));
      }
      const lines = entries.map((e) =>
        `${e.ts}  ${String(e.event).toUpperCase().padEnd(22)}` +
        `${e.anonymized_id ? " id=" + e.anonymized_id : ""}` +
        `${e.state ? " state=" + e.state : ""}`
      );
      res.setHeader("Content-Type", "text/plain");
      res.setHeader("Content-Disposition", 'attachment; filename="ble-tripwire-log.txt"');
      res.send("BLE Tripwire — audit log export\n" + new Date().toISOString() + "\n\n" + lines.join("\n") + "\n");
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  app.get("/api/sensors/ble-tripwire/audit/verify", (_req, res) => {
    res.json({ ok: true, ...verifyAuditChain() });
  });

  // TRIPWIRE: current unknown-emitter threat picture (deterministic, no model)
  app.get("/api/sensors/ble-tripwire/threats", (_req, res) => {
    try {
      const out = computeThreats();
      auditThreatTransitions(out.threats);
      res.json({ ok: true, ...out });
    } catch (err) {
      res.status(500).json({ ok: false, error: String(err.message || err) });
    }
  });

  console.log("[BLE-TRIPWIRE] ingest + analysis pipeline installed");
}

export default { installTripwire };



