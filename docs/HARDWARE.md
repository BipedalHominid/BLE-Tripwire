# BLE Tripwire — Hardware & Flashing Guide

The BLE Tripwire app is the **hub**. The actual sensing is done by one or more
**ESP32 boards** that you flash with the firmware in this repository and place
around the area you want to watch. The boards passively listen for Bluetooth
Low Energy advertisements and report what they hear to the app over your
phone's Wi-Fi hotspot. Nothing leaves your phone.

This guide takes you from "bought a board" to "seeing it on the dashboard."

---

## 1. What to buy

**Any BLE-capable ESP32 dev board works** — the classic ESP32 (ESP32-WROOM /
ESP32-DevKitC), ESP32-S3, ESP32-C3, etc. The firmware uses only the standard
ESP32 Arduino BLE and Wi-Fi APIs, nothing chip-specific. A classic **ESP32
DevKitC** is the cheapest common choice (~$6–12) and is what the app was
validated against; an **ESP32-S3 DevKitC** works identically. If you already
have an ESP32 in a drawer, use it.

> **One caveat that matters:** the firmware is ~1.7 MB, which is larger than
> the *default* ESP32 partition layout allows (~1.3 MB). You **must** select a
> partition scheme with a bigger app slot — "Huge App" — or the board will
> compile/flash but then boot-loop with `Image length ... doesn't fit in
> partition`. Sections 5 covers exactly where to set this. It's a one-time
> dropdown, but skipping it is the single most common way to get a dead node.

You also need a **USB cable** that carries data (not a charge-only cable) to
connect the board to your computer for flashing.

**How many?** One node already gives you a working tripwire. A second and third
node widen coverage and improve confidence (an emitter seen by two nodes is
more trustworthy than one). Three sketches are provided (`tripwire_node_01/02/03`),
pre-numbered so their reports don't collide.

---

## 2. Install the tools (one time)

1. Install the **Arduino IDE** (2.x) from arduino.cc.
2. Add ESP32 board support:
   - Arduino IDE → **Settings** → *Additional boards manager URLs*, add:
     `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
   - **Tools → Board → Boards Manager**, search **esp32**, install
     *"esp32 by Espressif Systems"*.
3. Add the one external library:
   - **Tools → Manage Libraries**, search **ArduinoJson** (by Benoit Blanchon),
     install it. (The BLE and Wi-Fi libraries come with the ESP32 core — no
     separate install.)

---

## 3. Get the firmware

Download the sketches from this repository — either clone it, or grab the
`.ino` files directly from the GitHub Release assets:

```
firmware/tripwire_node_01/tripwire_node_01.ino
firmware/tripwire_node_02/tripwire_node_02.ino   (optional 2nd node)
firmware/tripwire_node_03/tripwire_node_03.ino   (optional 3rd node)
```

Each `.ino` must stay in a folder of the same name (Arduino requires this) —
if you download a single file, put it in a folder named after it.

---

## 4. Edit two lines

Open `tripwire_node_01.ino` and set your phone's hotspot credentials near the
top:

```c
const char* ssid     = "YOUR_HOTSPOT_SSID";
const char* password = "YOUR_HOTSPOT_PASSWORD";
```

That's the only required change. Everything else auto-configures — the node
discovers the phone's address on the hotspot by itself and re-discovers it if
the network changes.

Optional knobs (fine to leave alone):

| Setting | Default | Meaning |
|---|---|---|
| `SENSOR_ID` | `ESP32-BLE-01` | Unique name per node — leave the per-file defaults as-is |
| `ZONE` | `Unassigned` | Free-text label if you want to tag where a node sits |
| `SCAN_SECONDS` | `25` | How long each listen sweep runs |
| `POST_DELAY_MS` | `30000` | Gap between reports (30 s) |
| `RSSI_THRESHOLD` | `-90` | Ignore signals weaker than this (raise toward -70 to only catch close devices) |

If you flash a second or third board, use `tripwire_node_02.ino` /
`tripwire_node_03.ino` — they already carry unique IDs.

---

## 5. Flash the board

### Option A — Arduino IDE

1. Plug the board into your computer.
2. **Tools → Board** → select your board (*ESP32 Dev Module* for a classic
   ESP32, *ESP32S3 Dev Module* for an S3).
3. **Tools → Partition Scheme → "Huge App (3MB No OTA/1MB SPIFFS)".**
   This is required — the default scheme is too small and the node will
   boot-loop. (If you don't see a Partition Scheme menu, you selected a generic
   board; pick "ESP32 Dev Module" rather than a named product.)
4. **Tools → Port** → pick the port that appeared when you plugged it in.
5. Click **Upload**. First upload compiles the ESP32 core and can take a few
   minutes.
   - If it hangs at "Connecting…", hold the board's **BOOT** button while it
     starts uploading, then release. Many classic ESP32 boards need this.

### Option B — arduino-cli (headless)

```bash
# one-time setup
arduino-cli config init
arduino-cli config add board_manager.additional_urls \
  https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
arduino-cli core update-index
arduino-cli core install esp32:esp32
arduino-cli lib install ArduinoJson

# compile + upload (note the huge_app partition — required)
arduino-cli compile --fqbn esp32:esp32:esp32:PartitionScheme=huge_app firmware/tripwire_node_01
arduino-cli upload -p /dev/ttyUSB0 --fqbn esp32:esp32:esp32:PartitionScheme=huge_app firmware/tripwire_node_01
```

The compile should report roughly **53%** of program storage. If it says
**over 100%** ("text section exceeds available space"), you left off the
`PartitionScheme=huge_app` — add it and re-flash, or the board won't boot.
For an S3, swap `esp32:esp32:esp32` for `esp32:esp32:esp32s3`.

---

## 6. Confirm it's working

Open **Tools → Serial Monitor**, set baud to **115200**. On a healthy node you'll see:

```
BLE Tripwire node 01 starting.
Connecting to Wi-Fi ...
WiFi connected. IP: 10.x.x.x
... scanning ...
Sending payload to server: http://10.x.x.x:8734/api/sensors/ble-tripwire
```

Then, **on your phone**:

1. Turn on your **Wi-Fi hotspot** (the SSID/password you put in the sketch).
2. Open the **BLE Tripwire** app. The setup banner is showing because no node
   has reported yet.
3. Within about a minute of the node connecting, it appears under **Sensor
   Network** as ONLINE and the setup banner disappears.

If it never shows up, check in this order:
- Serial monitor says *WiFi connected* — if not, the SSID/password is wrong.
- The phone's hotspot is actually on and the node joined it.
- The app is open (the sensor service runs while the app's foreground service
  notification is present).

---

## 7. Use it

1. Let it observe your normal surroundings for a few minutes.
2. In the app, tap **Capture baseline** — your own devices become KNOWN and
   stop triggering alerts.
3. From then on, unexpected emitters drive the tripwire states:
   **WATCH** (seen, distant/unconfirmed) → **ALERT** (confirmed inside your
   zone) → **CLOSING** (getting closer — signal rising). Every alert is written
   to a tamper-evident log you can verify in the app.

Place nodes near the boundaries you care about (a doorway, a driveway, a
hallway). More nodes = wider, more confident coverage.

---

## A note on what this is

This is a **presence and approach** detector, not a tracker or a positioning
system. Signal strength is not distance, one node cannot triangulate a
location, and modern phones randomize their Bluetooth addresses. BLE Tripwire
tells you *something unexpected is here and it's getting closer* — deliberately
and by design, it does not try to identify who or exactly where.

