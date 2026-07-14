package com.surfacevector.bletripwire;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "BLE-TRIPWIRE-UI";
    private static final int REQ_NOTIF = 100;

    private final String DASHBOARD_URL =
            "http://127.0.0.1:" + NodeService.PORT + "/dashboard.html";
    private final String HEALTH_URL =
            "http://127.0.0.1:" + NodeService.PORT + "/health";

    private WebView webView;
    private TextView statusView;
    private final Handler main = new Handler(Looper.getMainLooper());

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        webView = findViewById(R.id.webview);
        statusView = findViewById(R.id.status);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);          // dashboard uses sessionStorage
        s.setCacheMode(WebSettings.LOAD_NO_CACHE);
        s.setMediaPlaybackRequiresUserGesture(false); // tripwire audible alert

        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient() {
            @Override
            public void onProgressChanged(WebView view, int newProgress) {
                Log.d(TAG, "webview progress " + newProgress);
            }
        });

        setStatus("Starting sensor service\u2026");

        ensureNotificationPermission();
        startNodeService();
        requestBatteryExemption();

        waitForServerThenLoad();
    }

    // ---- service start -------------------------------------------------------

    private void startNodeService() {
        Intent svc = new Intent(this, NodeService.class);
        ContextCompat.startForegroundService(this, svc);
    }

    // ---- readiness poll ------------------------------------------------------

    private void waitForServerThenLoad() {
        setStatus("Waiting for on-device server on port " + NodeService.PORT + "\u2026");
        new Thread(() -> {
            final int maxAttempts = 120;      // ~30s at 250ms
            for (int i = 0; i < maxAttempts; i++) {
                if (pingHealth()) {
                    main.post(this::loadDashboard);
                    return;
                }
                try { Thread.sleep(250); } catch (InterruptedException ignored) { return; }
            }
            main.post(() -> setStatus(
                    "Server did not come up. Check logcat (tag BLE-TRIPWIRE-NODE).\n"
                            + "Tap to retry."));
            main.post(() -> statusView.setOnClickListener(v -> {
                statusView.setOnClickListener(null);
                waitForServerThenLoad();
            }));
        }, "health-poll").start();
    }

    private boolean pingHealth() {
        HttpURLConnection c = null;
        try {
            URL u = new URL(HEALTH_URL);
            c = (HttpURLConnection) u.openConnection();
            c.setConnectTimeout(1500);
            c.setReadTimeout(1500);
            c.setRequestMethod("GET");
            int code = c.getResponseCode();
            return code == 200;
        } catch (IOException e) {
            return false;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private void loadDashboard() {
        setStatus(null);
        webView.setVisibility(View.VISIBLE);
        webView.loadUrl(DASHBOARD_URL);
    }

    // ---- permissions / battery ----------------------------------------------

    private void ensureNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
            }
        }
    }

    /**
     * Ask the OS to exempt us from battery optimization. Without this, aggressive
     * OEM battery managers (Samsung, Xiaomi, etc.) can still freeze the service
     * despite the foreground notification + wake lock. Essential for a real
     * always-on tripwire.
     */
    @SuppressLint("BatteryLife")
    private void requestBatteryExemption() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null && !pm.isIgnoringBatteryOptimizations(getPackageName())) {
                Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
                i.setData(Uri.parse("package:" + getPackageName()));
                startActivity(i);
            }
        } catch (Throwable t) {
            Log.w(TAG, "battery exemption request failed (non-fatal)", t);
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        // Notification denial is non-fatal; the service still runs. The persistent
        // notification just won't be visible, which some OEMs then treat as more
        // killable — so it's worth granting.
    }

    // ---- misc ----------------------------------------------------------------

    private void setStatus(String text) {
        if (text == null) {
            statusView.setVisibility(View.GONE);
        } else {
            statusView.setVisibility(View.VISIBLE);
            statusView.setText(text);
        }
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.getVisibility() == View.VISIBLE && webView.canGoBack()) {
            webView.goBack();
        } else {
            // Don't kill the service; just background the UI. The tripwire keeps
            // running via the foreground service.
            moveTaskToBack(true);
        }
    }
}
