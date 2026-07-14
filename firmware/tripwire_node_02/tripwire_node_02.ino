#include <WiFi.h>
#include <WiFiClient.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

const char* ssid = "YOUR_HOTSPOT_SSID";
const char* password = "YOUR_HOTSPOT_PASSWORD";
// ===========================================================================
// PHONE HOTSPOT TARGET — resolved AUTOMATICALLY at runtime.
// On a hotspot, the gateway the phone's DHCP hands this ESP32 IS the phone
// itself (e.g. Samsung swlan0 10.220.81.47), so connectWifi() rebuilds
// serverUrl from WiFi.gatewayIP() after every (re)connect. This self-heals
// when Android re-randomizes the hotspot subnet between sessions.
// PHONE_GATEWAY_FALLBACK is used only if the gateway can't be read.
// PORT must match NodeService.PORT / server.js PORT (default 8734).
#define PHONE_GATEWAY_FALLBACK "192.168.43.1"
#define TRIPWIRE_PORT             "8734"
String serverUrl = "http://" PHONE_GATEWAY_FALLBACK ":" TRIPWIRE_PORT "/api/sensors/ble-tripwire";
const char* SENSOR_ID = "ESP32-BLE-02";

// Set this per-deployment. Independent zones are fine — the backend keys
// observations by sensor_id/zone, no overlap with the other node required.
const char* ZONE = "Unassigned";

// Passive = no scan requests sent, sensor is invisible to scanned devices.
// Active = sends scan requests, can pick up SCAN_RSP-only fields (e.g. full
// name on some devices) but reveals the sensor's presence. BLE-TRIPWIRE's
// backend already declares itself "defensive_passive_local_only" in its
// safety_boundary block, so passive is the correct default here.
static const bool PASSIVE_SCAN = true;

static const int SCAN_SECONDS = 25;
static const int POST_DELAY_MS = 30000;
static const int MAX_DEVICES = 40;
static const int RSSI_THRESHOLD = -90;  // ignore devices weaker than this

struct BleRecord {
  String mac;
  int rssi = -127;
  String name = "";
  String addressType = "unknown";
  String manufacturerDataHex = "";
  String serviceUuids = "";
  int8_t txPower = 0;
  bool haveTxPower = false;
};

BleRecord foundDevices[MAX_DEVICES];
int foundCount = 0;

// Real hardware-level PAUSE/RESUME — set by checkSerialCommand() when the
// backend writes "PAUSE\n"/"RESUME\n" over this same serial line.
bool sensorPaused = false;
String serialLineBuf = "";

String hexEncode(const String& data) {
  static const char hexChars[] = "0123456789ABCDEF";
  String out;
  out.reserve(data.length() * 2);
  for (size_t i = 0; i < data.length(); i++) {
    unsigned char c = (unsigned char)data[i];
    out += hexChars[(c >> 4) & 0xF];
    out += hexChars[c & 0xF];
  }
  return out;
}

String addressTypeToString(uint8_t t) {
  switch (t) {
    case 0x00: return "public";
    case 0x01: return "random_static_or_private";
    case 0x02: return "random_resolvable_public_identity";
    case 0x03: return "random_resolvable_private";
    default:   return "unknown";
  }
}

// Non-blocking: drains whatever is in the Serial RX buffer right now and
// acts on a complete "PAUSE" or "RESUME" line. Anything else is ignored.
void checkSerialCommand() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      if (serialLineBuf.length() > 0) {
        serialLineBuf.trim();
        if (serialLineBuf == "PAUSE") {
          sensorPaused = true;
          Serial.println("[ctrl] PAUSE received -- holding scan cycle.");
        } else if (serialLineBuf == "RESUME") {
          sensorPaused = false;
          Serial.println("[ctrl] RESUME received -- resuming scan cycle.");
        }
        serialLineBuf = "";
      }
    } else {
      serialLineBuf += c;
      if (serialLineBuf.length() > 32) serialLineBuf = ""; // guard against junk/noise
    }
  }
}

class TripwireCallbacks : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice advertisedDevice) override {
    if (advertisedDevice.getRSSI() < RSSI_THRESHOLD) return;

    String mac = advertisedDevice.getAddress().toString().c_str();
    mac.toUpperCase();

    int idx = -1;
    for (int i = 0; i < foundCount; i++) {
      if (foundDevices[i].mac == mac) { idx = i; break; }
    }

    if (idx == -1) {
      if (foundCount >= MAX_DEVICES) return;
      idx = foundCount++;
      foundDevices[idx] = BleRecord();
      foundDevices[idx].mac = mac;
      foundDevices[idx].rssi = advertisedDevice.getRSSI();
    } else if (advertisedDevice.getRSSI() > foundDevices[idx].rssi) {
      // keep the strongest signal observed for this device during the scan
      foundDevices[idx].rssi = advertisedDevice.getRSSI();
    }

    BleRecord& rec = foundDevices[idx];

    if (advertisedDevice.haveName() && rec.name.length() == 0) {
      rec.name = advertisedDevice.getName().c_str();
    }

    if (advertisedDevice.haveManufacturerData() && rec.manufacturerDataHex.length() == 0) {
      rec.manufacturerDataHex = hexEncode(advertisedDevice.getManufacturerData());
    }

    if (advertisedDevice.haveServiceUUID() && rec.serviceUuids.length() == 0) {
      String list = "";
      int count = advertisedDevice.getServiceUUIDCount();
      for (int i = 0; i < count; i++) {
        if (i > 0) list += ",";
        list += advertisedDevice.getServiceUUID(i).toString().c_str();
      }
      rec.serviceUuids = list;
    }

    if (advertisedDevice.haveTXPower()) {
      rec.txPower = advertisedDevice.getTXPower();
      rec.haveTxPower = true;
    }

    rec.addressType = addressTypeToString(advertisedDevice.getAddressType());

    Serial.print("BLE seen: ");
    Serial.print(rec.mac);
    Serial.print(" RSSI=");
    Serial.print(rec.rssi);
    Serial.print(" addrType=");
    Serial.print(rec.addressType);
    if (rec.name.length()) {
      Serial.print(" name=");
      Serial.print(rec.name);
    }
    if (rec.manufacturerDataHex.length()) {
      Serial.print(" mfg=");
      Serial.print(rec.manufacturerDataHex);
    }
    Serial.println();
  }
};

BLEScan* pBLEScan = nullptr;

void onWifiEvent(WiFiEvent_t event, WiFiEventInfo_t info) {
  if (event == ARDUINO_EVENT_WIFI_STA_DISCONNECTED) {
    Serial.print("  -> STA disconnect reason: ");
    Serial.println(info.wifi_sta_disconnected.reason);
  }
}

void connectWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  Serial.print("Connecting to WiFi: ");
  Serial.println(ssid);

  WiFi.onEvent(onWifiEvent);
  WiFi.disconnect(true);
  delay(1000);

  WiFi.mode(WIFI_STA);
  WiFi.setSleep(false);
  WiFi.begin(ssid, password);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 80) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.print("WiFi Connected! ESP32 IP: ");
    Serial.println(WiFi.localIP());

    // On a hotspot the gateway IS the phone's AP address, whatever subnet
    // Android picked this session — rebuild the POST target from it.
    IPAddress gw = WiFi.gatewayIP();
    if (gw != IPAddress(0, 0, 0, 0)) {
      serverUrl = String("http://") + gw.toString() + ":" TRIPWIRE_PORT "/api/sensors/ble-tripwire";
    } else {
      Serial.println("Gateway unreadable -- keeping fallback serverUrl.");
    }
    Serial.print("Posting to: ");
    Serial.println(serverUrl);
  } else {
    Serial.println("WiFi connection failed.");
  }
}

void postToServer() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWifi();
    if (WiFi.status() != WL_CONNECTED) return;
  }

  JsonDocument doc;
  JsonArray devices = doc["devices"].to<JsonArray>();

  for (int i = 0; i < foundCount; i++) {
    BleRecord& rec = foundDevices[i];
    JsonObject deviceObj = devices.add<JsonObject>();
    deviceObj["mac"] = rec.mac;
    deviceObj["rssi"] = rec.rssi;
    deviceObj["name"] = rec.name;
    deviceObj["sensor_id"] = SENSOR_ID;
    deviceObj["zone"] = ZONE;
    deviceObj["address_type"] = rec.addressType;

    bool haveMfg = rec.manufacturerDataHex.length() > 0;
    deviceObj["manufacturer_data_present"] = haveMfg;
    if (haveMfg) {
      deviceObj["manufacturer_data"] = rec.manufacturerDataHex;
    }

    if (rec.serviceUuids.length() > 0) {
      deviceObj["service_uuids"] = rec.serviceUuids;
    }

    if (rec.haveTxPower) {
      deviceObj["tx_power"] = rec.txPower;
    }
  }

  String jsonPayload;
  serializeJson(doc, jsonPayload);

  Serial.print("Sending payload to server: ");
  Serial.println(jsonPayload);

  WiFiClient client; // plain HTTP to the phone hotspot on the local LAN

  HTTPClient http;
  http.begin(client, serverUrl);
  http.addHeader("Content-Type", "application/json");

  int httpResponseCode = http.POST(jsonPayload);

  Serial.print("HTTP Response code: ");
  Serial.println(httpResponseCode);

  String response = http.getString();
  if (response.length() > 0) {
    Serial.print("Response: ");
    Serial.println(response);
  }

  http.end();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("BLE Tripwire node 02 starting.");

  Serial.printf("Chip model: %s (rev %d, %d cores)\n",
                ESP.getChipModel(), ESP.getChipRevision(), ESP.getChipCores());
  Serial.printf("IDF version: %s\n", esp_get_idf_version());

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(200);

  Serial.println("Scanning for APs...");
  int n = WiFi.scanNetworks();
  for (int i = 0; i < n; i++) {
    Serial.printf("  %2d: %-32s  ch%2d  %4d dBm  %s\n",
      i, WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i),
      WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "open" : "enc");
  }
  WiFi.scanDelete();

  connectWifi();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.print("Final WiFi status code: ");
    Serial.println(WiFi.status());
  }

  BLEDevice::init("BLE-Tripwire-02");
  pBLEScan = BLEDevice::getScan();
  pBLEScan->setAdvertisedDeviceCallbacks(new TripwireCallbacks());
  pBLEScan->setActiveScan(!PASSIVE_SCAN);
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99);
}

void loop() {
  checkSerialCommand();

  if (sensorPaused) {
    delay(500); // idle in short increments so RESUME is caught promptly
    return;
  }

  foundCount = 0;

  Serial.println("Starting BLE scan...");
  pBLEScan->start(SCAN_SECONDS, false);
  pBLEScan->clearResults();

  // A PAUSE sent while the scan above was running (it blocks for
  // SCAN_SECONDS) gets caught here, before we transmit anything.
  checkSerialCommand();
  if (sensorPaused) {
    Serial.println("Paused at end of scan -- skipping POST this cycle.");
    return;
  }

  Serial.print("Scan complete. Devices found: ");
  Serial.println(foundCount);

  if (foundCount > 0) {
    postToServer();
  } else {
    Serial.println("No BLE devices found.");
  }

  unsigned long waited = 0;
  while (waited < (unsigned long)POST_DELAY_MS) {
    checkSerialCommand();
    if (sensorPaused) break;
    delay(200);
    waited += 200;
  }
}

