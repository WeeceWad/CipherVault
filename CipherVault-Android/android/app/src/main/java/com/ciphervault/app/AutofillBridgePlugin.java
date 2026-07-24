package com.ciphervault.app;

import android.content.Context;
import android.os.Build;
import android.view.autofill.AutofillManager;

import com.getcapacitor.JSArray;
import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The one-way bridge from the unlocked vault to the native autofill cache.
 *
 * The web layer decrypts the vault, then hands this plugin just the login
 * entries (title, username, password, url). AutofillStore re-encrypts them
 * with a key that only works just after a biometric, so the cache is useless
 * at rest. Notes, folders and everything else never leave the WebView.
 *
 * Nothing here can read the cache back - decryption lives in the autofill
 * service behind its own biometric gate. This plugin only writes and clears.
 */
@CapacitorPlugin(name = "AutofillBridge")
public class AutofillBridgePlugin extends Plugin {

    /** Whether the device even has an autofill framework (API 26+). */
    @PluginMethod
    public void isSupported(PluginCall call) {
        JSObject result = new JSObject();
        boolean supported = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            && getContext().getSystemService(AutofillManager.class) != null;
        result.put("supported", supported);
        call.resolve(result);
    }

    /** Whether CipherVault is the currently selected autofill service. */
    @PluginMethod
    public void isEnabled(PluginCall call) {
        JSObject result = new JSObject();
        boolean enabled = false;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            AutofillManager mgr = getContext().getSystemService(AutofillManager.class);
            enabled = mgr != null && mgr.hasEnabledAutofillServices();
        }
        result.put("enabled", enabled);
        result.put("count", AutofillStore.count(getContext()));
        call.resolve(result);
    }

    /**
     * Replaces the cached logins. Called whenever the vault is unlocked or its
     * contents change, so autofill always reflects the latest vault.
     */
    @PluginMethod
    public void setCredentials(PluginCall call) {
        JSArray items = call.getArray("items");
        if (items == null) {
            call.reject("No items supplied");
            return;
        }

        try {
            JSONArray sanitised = new JSONArray();
            for (int i = 0; i < items.length(); i++) {
                JSONObject src = items.getJSONObject(i);

                // A login is only useful to autofill with a password; a title
                // alone is noise in the dropdown.
                String password = src.optString("password", "");
                if (password.isEmpty()) continue;

                JSONObject entry = new JSONObject();
                entry.put("title", src.optString("title", ""));
                entry.put("username", src.optString("username", ""));
                entry.put("password", password);
                entry.put("url", src.optString("url", ""));
                sanitised.put(entry);
            }

            AutofillStore.save(getContext(), sanitised);

            JSObject result = new JSObject();
            result.put("count", sanitised.length());
            call.resolve(result);
        } catch (Exception e) {
            call.reject("Could not store credentials: " + e.getMessage(), e);
        }
    }

    /** Forgets the cache and destroys its key. Called on lock and sign-out. */
    @PluginMethod
    public void clear(PluginCall call) {
        AutofillStore.wipe(getContext());
        call.resolve();
    }

    /** Opens the system screen to pick the autofill service. */
    @PluginMethod
    public void openSettings(PluginCall call) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                android.content.Intent intent =
                    new android.content.Intent(android.provider.Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE);
                intent.setData(android.net.Uri.parse("package:" + getContext().getPackageName()));
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                getContext().startActivity(intent);
            }
        } catch (Exception e) {
            // Some OEMs bury the setting; fall back to the general one.
            try {
                android.content.Intent fallback =
                    new android.content.Intent(android.provider.Settings.ACTION_SETTINGS);
                fallback.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK);
                getContext().startActivity(fallback);
            } catch (Exception ignored) { }
        }
        call.resolve();
    }
}
