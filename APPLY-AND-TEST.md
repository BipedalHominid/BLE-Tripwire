# BLE Tripwire v1.2 — apply & test

## Apply
```bash
cd ~/horus-v5/ble-tripwire
unzip -o ~/Downloads/tw-v1.2.zip -d /tmp/tw12
cp -r /tmp/tw12/tw-v1.2/* .

# APK SHRINK: remove the x86_64 Node runtime (emulator-only) so the APK ~halves
rm -rf app/src/main/jniLibs/x86_64

# bump version so the phone re-extracts the new dashboard/pipeline
# (edit app/build.gradle: versionCode 2 -> 3, versionName -> "1.2.0")

./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk    # or http.server + phone
# check the size drop yourself:
ls -la app/build/outputs/apk/debug/app-debug.apk
```
Force-stop the app and reopen so the service re-extracts assets.

## Per-feature test checklist (verify on the phone)

1. **APK shrink** — `ls -la` shows the debug APK notably smaller than 55 MB (expect high-20s/low-30s MB).
2. **Log spam fixed** — drag the sensitivity sliders a few times, open History. No "Sensitivity changed" entries should appear anymore.
3. **Arm/disarm** — top-left "Armed" toggle. Tap → "Disarmed". While disarmed, an ALERT should NOT push a notification (but still shows in the app + history). Re-arm → notifications resume. History logs armed/disarmed.
4. **Schedule** — Alert schedule section → enable, set a window that EXCLUDES now → alerts stay silent; set a window that INCLUDES now → alerts fire. "Armed · sched" shows on the button.
5. **Audio** — with an ALERT/CLOSING firing while armed, the notification should make sound + vibrate (uses your phone's default notification tone; check the "Tripwire alerts" channel isn't muted).
6. **Device naming** — tap any signal row → prompt → type a name → row shows the name with hex underneath. Persists after app restart.
7. **Dwell/return** — leave an unknown device near a node a couple minutes → row shows "here 2m"; take it away and bring it back → "seen 2×".
8. **Export** — History → "Export log (text)" / "Export CSV" → should download a file via the system downloader.
9. **Audit chain** — History chip still says "log intact". Naming/arming don't break it.

## If something misbehaves
- Dwell/return is the most experimental. If it acts odd, it's isolated in `_tripwireTrackReturns` / the `dwell_sec`+`return_count` fields in computeThreats — safe to ignore or pull without affecting the rest.
- Audio depends on your phone's channel settings; if silent, check Settings → Apps → BLE Tripwire → Notifications → "Tripwire alerts" channel sound.
