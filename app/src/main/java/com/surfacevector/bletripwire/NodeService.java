package com.surfacevector.bletripwire;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Runs the BLE-TRIPWIRE Node bundle as an Android foreground service so the OS
 * does not kill it in Doze / with the screen off. This is what makes the app a
 * real tripwire rather than a foreground-only viewer.
 *
 * Responsibilities:
 *   - extract assets/nodejs-project -> filesDir/nodejs-project on first run and
 *     on app upgrade (writable data lives OUTSIDE that dir so it survives).
 *   - acquire a partial wake lock (CPU stays up so the ServerSocket keeps
 *     accepting) + a WifiLock so hotspot ingest keeps flowing.
 *   - start node::Start on a dedicated thread and keep it alive.
 */
public class NodeService extends Service {

    public static final String TAG = "BLE-TRIPWIRE-SVC";

    // On-device server port. MUST match server.js PORT, the WebView URL in
    // MainActivity, and the ESP32 sketches' serverUrl.
    public static final int PORT = 8734;

    public static final String ACTION_STOP = "com.surfacevector.bletripwire.STOP";

    private static final String CHANNEL_ID = "tripwire_service";
    private static final String ALERT_CHANNEL_ID = "tripwire_alerts";
    private static final int NOTIF_ID = 4201;
    private static final int ALERT_NOTIF_ID = 4202;
    private static final long ALERT_POLL_MS = 20_000;

    private Thread nodeThread;
    private volatile boolean nodeStarted = false;

    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;

    private Thread alertThread;
    private volatile boolean alertPolling = false;
    // anonymized_id -> last state we notified for; avoids re-alerting every poll.
    private final Map<String, String> lastNotifiedState = new HashMap<>();

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopEverythingAndSelf();
            return START_NOT_STICKY;
        }

        startForegroundCompat();
        acquireLocks();
        startNodeOnce();
        startAlertPollerOnce();

        // If the OS kills us for memory, come back and restart Node.
        return START_STICKY;
    }

    // ---- Node lifecycle ------------------------------------------------------

    private synchronized void startNodeOnce() {
        if (nodeStarted) return;
        nodeStarted = true;

        nodeThread = new Thread(() -> {
            try {
                File nodeDir = new File(getFilesDir(), "nodejs-project");
                File dataDir = new File(getFilesDir(), "tripwire_data");
                if (!dataDir.exists() && !dataDir.mkdirs()) {
                    Log.w(TAG, "could not create data dir: " + dataDir);
                }

                extractNodeProjectIfNeeded(nodeDir);

                File entry = new File(nodeDir, "main.js");
                if (!entry.exists()) {
                    Log.e(TAG, "entry script missing: " + entry);
                    return;
                }

                NodeBridge.ensureLoaded();
                NodeBridge bridge = new NodeBridge();

                Log.i(TAG, "starting Node: entry=" + entry.getAbsolutePath()
                        + " data=" + dataDir.getAbsolutePath() + " port=" + PORT);

                // argv[0]="node" is conventional; entry + data dir + port follow.
                int code = bridge.startNodeWithArguments(new String[]{
                        "node",
                        entry.getAbsolutePath(),
                        dataDir.getAbsolutePath(),
                        String.valueOf(PORT)
                });

                // node::Start only returns if Node exits — which for a server is
                // abnormal. Log it; START_STICKY will bring the service back.
                Log.w(TAG, "Node exited with code " + code);
            } catch (Throwable t) {
                Log.e(TAG, "Node thread crashed", t);
            }
        }, "ble-tripwire-node");
        nodeThread.setDaemon(true);
        nodeThread.start();
    }

    // ---- asset extraction ----------------------------------------------------

    /**
     * Extract the bundled Node project to {@code nodeDir}, but only when missing
     * or when the app version changed (so upgrades ship new JS). The writable
     * data dir is separate and never touched here.
     */
    private void extractNodeProjectIfNeeded(File nodeDir) {
        int versionCode = appVersionCode();
        File marker = new File(nodeDir, ".bundle-version");

        boolean upToDate = false;
        if (nodeDir.isDirectory() && marker.exists()) {
            try {
                String stored = readSmallFile(marker).trim();
                upToDate = stored.equals(String.valueOf(versionCode));
            } catch (IOException ignored) {}
        }
        if (upToDate) {
            Log.i(TAG, "node project already extracted for version " + versionCode);
            return;
        }

        Log.i(TAG, "extracting node project (version " + versionCode + ")...");
        deleteRecursive(nodeDir);
        if (!nodeDir.mkdirs()) {
            Log.w(TAG, "could not create node dir: " + nodeDir);
        }
        try {
            copyAssetDir("nodejs-project", nodeDir);
            try (OutputStream os = new FileOutputStream(marker)) {
                os.write(String.valueOf(versionCode).getBytes());
            }
            Log.i(TAG, "node project extracted.");
        } catch (IOException e) {
            Log.e(TAG, "asset extraction failed", e);
        }
    }

    private void copyAssetDir(String assetPath, File outDir) throws IOException {
        String[] children = getAssets().list(assetPath);
        if (children == null) return;

        if (children.length == 0) {
            // It's a file, not a directory.
            copyAssetFile(assetPath, outDir);
            return;
        }
        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IOException("mkdir failed: " + outDir);
        }
        for (String child : children) {
            String childAsset = assetPath + "/" + child;
            File childOut = new File(outDir, child);
            String[] grand = getAssets().list(childAsset);
            if (grand != null && grand.length > 0) {
                copyAssetDir(childAsset, childOut);
            } else {
                // Could be an empty dir or a file; try as file, fall back to dir.
                try (InputStream ignored = getAssets().open(childAsset)) {
                    copyAssetFile(childAsset, childOut);
                } catch (IOException notAFile) {
                    if (!childOut.exists() && !childOut.mkdirs()) {
                        throw new IOException("mkdir failed: " + childOut);
                    }
                    copyAssetDir(childAsset, childOut);
                }
            }
        }
    }

    private void copyAssetFile(String assetPath, File outFile) throws IOException {
        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("mkdir failed: " + parent);
        }
        byte[] buf = new byte[16 * 1024];
        try (InputStream is = getAssets().open(assetPath);
             OutputStream os = new FileOutputStream(outFile)) {
            int n;
            while ((n = is.read(buf)) != -1) os.write(buf, 0, n);
        }
    }

    // ---- locks ---------------------------------------------------------------

    private void acquireLocks() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null && wakeLock == null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK,
                        "Tripwire::NodeWakeLock");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire();
            }

            WifiManager wm = (WifiManager) getApplicationContext()
                    .getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                if (wifiLock == null) {
                    wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF,
                            "Tripwire::WifiLock");
                    wifiLock.setReferenceCounted(false);
                    wifiLock.acquire();
                }
            }
            Log.i(TAG, "locks acquired (wake/wifi)");
        } catch (Throwable t) {
            Log.w(TAG, "acquireLocks failed", t);
        }
    }

    private void releaseLocks() {
        try { if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); } catch (Throwable ignored) {}
        try { if (wifiLock != null && wifiLock.isHeld()) wifiLock.release(); } catch (Throwable ignored) {}
        wakeLock = null; wifiLock = null;
    }

    // ---- notification / foreground ------------------------------------------

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Sensor service",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Keeps the passive BLE tripwire ingesting with the screen off.");
            channel.setShowBadge(false);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);

                NotificationChannel alerts = new NotificationChannel(
                        ALERT_CHANNEL_ID,
                        "Tripwire alerts",
                        NotificationManager.IMPORTANCE_HIGH);
                alerts.setDescription("Heads-up when an unknown device enters your zone or approaches.");
                alerts.enableVibration(true);
                nm.createNotificationChannel(alerts);
            }
        }
    }

    private Notification buildNotification() {
        Intent openIntent = new Intent(this, MainActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        PendingIntent openPending = PendingIntent.getActivity(
                this, 0, openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Intent stopIntent = new Intent(this, NodeService.class);
        stopIntent.setAction(ACTION_STOP);
        PendingIntent stopPending = PendingIntent.getService(
                this, 1, stopIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);

        return b
                .setContentTitle("BLE-TRIPWIRE active")
                .setContentText("Passive BLE tripwire ingesting on port " + PORT)
                .setSmallIcon(R.drawable.ic_stat_tripwire)
                .setOngoing(true)
                .setContentIntent(openPending)
                .addAction(new Notification.Action.Builder(
                        null, "Stop", stopPending).build())
                .build();
    }

    private void startForegroundCompat() {
        Notification n = buildNotification();
        if (Build.VERSION.SDK_INT >= 34) { // Android 14+: must pass a type
            startForeground(NOTIF_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTIF_ID, n);
        }
    }

    private void stopEverythingAndSelf() {
        Log.i(TAG, "stop requested");
        releaseLocks();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(Service.STOP_FOREGROUND_REMOVE);
        } else {
            stopForeground(true);
        }
        stopSelf();
        // nodejs-mobile has no external clean-stop hook we hold a reference to,
        // and node::Start is blocking its thread. For this single-purpose
        // appliance the reliable way to actually halt ingestion is to tear down
        // the process. On-disk state (observations/audit) is append-only and
        // consistent, so an abrupt exit is safe. Relaunch the app to start again.
        new android.os.Handler(Looper.getMainLooper()).postDelayed(() -> {
            android.os.Process.killProcess(android.os.Process.myPid());
        }, 300);
    }

    @Override
    public void onDestroy() {
        alertPolling = false;
        releaseLocks();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    // ---- escalation notifications --------------------------------------------

    /**
     * Poll the local pipeline's /threats endpoint and raise a heads-up
     * notification whenever an emitter newly enters ALERT or CLOSING. The
     * pipeline itself can't post Android notifications; this thin poller is
     * the bridge. Everything stays on 127.0.0.1 — no network egress.
     */
    private synchronized void startAlertPollerOnce() {
        if (alertPolling) return;
        alertPolling = true;
        alertThread = new Thread(() -> {
            // Give Node a moment to boot before the first poll.
            sleepQuietly(15_000);
            while (alertPolling) {
                try {
                    pollThreatsAndNotify();
                } catch (Throwable t) {
                    Log.w(TAG, "alert poll failed: " + t.getMessage());
                }
                sleepQuietly(ALERT_POLL_MS);
            }
        }, "ble-tripwire-alerts");
        alertThread.setDaemon(true);
        alertThread.start();
    }

    private void pollThreatsAndNotify() throws IOException {
        HttpURLConnection c = (HttpURLConnection)
                new URL("http://127.0.0.1:" + PORT + "/api/sensors/ble-tripwire/threats").openConnection();
        c.setConnectTimeout(4000);
        c.setReadTimeout(6000);
        try (BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line);

            JSONObject d = new JSONObject(sb.toString());
            JSONArray threats = d.optJSONArray("threats");
            if (threats == null) return;

            int escalations = 0;
            String headline = null;
            boolean anyClosing = false;

            Map<String, String> current = new HashMap<>();
            for (int i = 0; i < threats.length(); i++) {
                JSONObject t = threats.getJSONObject(i);
                if (t.optBoolean("known", false)) continue;
                String id = t.optString("id", "");
                String state = t.optString("state", "");
                current.put(id, state);

                boolean isEscalated = "ALERT".equals(state) || "CLOSING".equals(state);
                String prev = lastNotifiedState.get(id);
                boolean wasEscalated = "ALERT".equals(prev) || "CLOSING".equals(prev);

                if (isEscalated && !wasEscalated) {
                    escalations++;
                    if ("CLOSING".equals(state)) anyClosing = true;
                    String shortId = id.replaceFirst("^DEV-", "");
                    if (shortId.length() > 10) shortId = shortId.substring(0, 10);
                    headline = "CLOSING".equals(state)
                            ? "Signal approaching — " + shortId + " getting stronger ("
                              + t.optInt("rssi_last_dbm", 0) + " dBm)"
                            : "Unknown device inside your zone — " + shortId + " ("
                              + t.optInt("rssi_max_dbm", 0) + " dBm)";
                }
            }
            // forget emitters that left the window so a return re-alerts
            lastNotifiedState.keySet().retainAll(current.keySet());
            lastNotifiedState.putAll(current);

            if (escalations > 0 && headline != null) {
                String title = anyClosing ? "Tripwire — closing" : "Tripwire — alert";
                String text = escalations == 1
                        ? headline
                        : escalations + " unknown signals escalated. " + headline;
                postAlertNotification(title, text);
            }
        } catch (org.json.JSONException e) {
            Log.w(TAG, "alert poll: bad JSON: " + e.getMessage());
        } finally {
            c.disconnect();
        }
    }

    private void postAlertNotification(String title, String text) {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(
                this, 1, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, ALERT_CHANNEL_ID);
        } else {
            b = new Notification.Builder(this).setPriority(Notification.PRIORITY_HIGH);
        }
        b.setSmallIcon(R.drawable.ic_stat_tripwire)
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(new Notification.BigTextStyle().bigText(text))
                .setContentIntent(pi)
                .setAutoCancel(true);

        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null) nm.notify(ALERT_NOTIF_ID, b.build());
    }

    private static void sleepQuietly(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    // ---- small helpers -------------------------------------------------------

    private int appVersionCode() {
        try {
            return (int) getPackageManager()
                    .getPackageInfo(getPackageName(), 0).getLongVersionCode();
        } catch (Exception e) {
            return 1;
        }
    }

    private String readSmallFile(File f) throws IOException {
        byte[] buf = new byte[(int) f.length()];
        try (InputStream is = new java.io.FileInputStream(f)) {
            int off = 0, n;
            while (off < buf.length && (n = is.read(buf, off, buf.length - off)) > 0) off += n;
        }
        return new String(buf);
    }

    private void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        File[] kids = f.listFiles();
        if (kids != null) for (File k : kids) deleteRecursive(k);
        // noinspection ResultOfMethodCallIgnored
        f.delete();
    }
}
