# BLE Tripwire

**A passive, camera-free perimeter tripwire. Your phone is the hub; cheap
ESP32-S3 boards are the ears. Everything runs on-device — no cloud, no
account, no camera, no AI.**

ESP32-S3 sensor nodes passively listen for Bluetooth Low Energy advertisements
(phones, wearables, trackers) and POST sightings to your phone over the phone's
own Wi-Fi hotspot. An embedded Node.js pipeline on the phone anonymizes,
analyzes, and runs a deterministic zone-breach state machine, and a local
dashboard shows you what's happening. When an unknown emitter enters your zone
— or is *approaching* (rising signal strength across sweeps) — you know.

## What it honestly is (and is not)

- **Is:** a presence-and-approach tripwire. Unknown emitter near a sensor →
  WATCH. Confirmed inside the zone RSSI threshold → ALERT. Signal strength
  trending up → CLOSING (highest priority).
- **Is not:** a tracker or positioning system. RSSI is not distance. One
  sensor cannot triangulate. Modern phones randomize their BLE addresses, so a
  determined, aware subject is not reliably re-identifiable — and this app
  does not try. Device addresses are HMAC-anonymized at ingest with a
  per-install random key.

## Architecture

```
ESP32-S3 node(s) ──(phone hotspot Wi-Fi)──► POST /api/sensors/ble-tripwire
                                                    │
                                       Node.js (nodejs-mobile, on-device)
                                       • HMAC anonymization (per-install key)
                                       • data-sufficiency gate
                                       • baseline compare
                                       • zone-breach state machine
                                       • HMAC-chained tamper-evident audit log
                                                    │
                                       WebView dashboard (localhost only)
```

The Android app is a thin shell: a foreground service keeps the Node process
alive through Doze/screen-off, and a WebView shows the dashboard from
`http://127.0.0.1:8734`. Nothing leaves the phone.

## Build

Prereqs: Android Studio (SDK 34, NDK + CMake via SDK Manager, JDK 17),
plus `bash`/`curl`/`unzip` for the one-time libnode fetch.

```bash
scripts/fetch-libnode.sh     # downloads pinned nodejs-mobile v18.20.4 libnode.so
```

Then open the project in Android Studio and Run, or:

```bash
./gradlew assembleDebug      # debug-signed APK, sideloadable as-is
```

(F-Droid main-repo builds can't use the prebuilt libnode.so — see
[FDROID.md](FDROID.md) for the from-source recipe path and interim
distribution options.)

## Sensor nodes

Firmware for three nodes is in `firmware/` (Arduino sketches, ESP32 board
package). Before flashing, edit the two lines at the top of each sketch:

```c
const char* ssid     = "YOUR_HOTSPOT_SSID";
const char* password = "YOUR_HOTSPOT_PASSWORD";
```

Set these to your phone's hotspot credentials. The nodes join the hotspot and
POST to the phone's gateway IP automatically (they re-derive it after every
reconnect, so OEM subnet differences self-heal). Scanning is passive only —
the nodes never transmit scan requests and never connect to observed devices.

## Using it

1. Start the app; the notification means the service is ingesting.
2. Power the nodes near the perimeter you care about.
3. Let it observe your normal environment for a few minutes, then hit
   **Capture baseline** in the dashboard — your own devices become KNOWN.
4. From then on, unknown emitters drive WATCH / ALERT / CLOSING states, and
   every alert transition is written to the tamper-evident audit chain
   (verify anytime via the dashboard or `GET /api/sensors/ble-tripwire/audit/verify`).

Tuning knobs (environment variables, all optional): `BLE_TRIPWIRE_ZONE_DBM`
(zone RSSI threshold, default −78), `BLE_TRIPWIRE_CONFIRM_SWEEPS` (default 2),
`BLE_TRIPWIRE_APPROACH_DB` (rising-trend threshold, default 4),
`BLE_TRIPWIRE_TRIPWIRE_WINDOW_SEC` (default 120).

## Privacy posture

- Per-install random HMAC keys (generated on first launch, stored 0600 in the
  app's private dir) — anonymized IDs are not comparable across installs and
  not derivable from this public source.
- The audit chain is keyed with a second per-install random secret, so the
  integrity check means something.
- No outbound network traffic. The server binds the phone's interfaces so
  hotspot sensors can reach it; the only consumers are the in-app WebView and
  your own nodes.

## License

GPL-3.0 — see [LICENSE](LICENSE).
