package com.ciphervault.app;

import android.os.Bundle;
import android.view.WindowManager;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {

    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Local plugins must be registered before the bridge starts.
        registerPlugin(AppUpdaterPlugin.class);

        super.onCreate(savedInstanceState);

        // FLAG_SECURE keeps the vault out of the recent-apps thumbnail and
        // blocks screenshots and screen recording while it is on screen.
        // For a password manager, an unlocked vault sitting in the app
        // switcher is a real exposure.
        getWindow().setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        );
    }
}
