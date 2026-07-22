package com.ciphervault.app;

import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;

import androidx.core.content.FileProvider;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Self-update support for the sideloaded APK.
 *
 * CipherVault is distributed through GitHub Releases rather than the Play
 * Store, so it has to fetch and install its own updates. The JS layer decides
 * *whether* to update (see www/js/updater.js); this class does the two things
 * JavaScript cannot: download to app-private storage and hand the file to
 * Android's package installer.
 *
 * Download URLs are checked against a host allowlist. The URL originates from
 * the GitHub API, but if the web layer were ever compromised this stops it
 * being used to install an arbitrary APK from anywhere on the internet.
 */
@CapacitorPlugin(name = "AppUpdater")
public class AppUpdaterPlugin extends Plugin {

    private static final List<String> ALLOWED_HOSTS = Arrays.asList(
        "github.com",
        "www.github.com",
        "api.github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com",
        "codeload.github.com"
    );

    private static final int MAX_REDIRECTS = 5;
    private static final int CONNECT_TIMEOUT_MS = 20000;
    private static final int READ_TIMEOUT_MS = 60000;

    /** Installed versionName / versionCode, plus whether we may install packages. */
    @PluginMethod
    public void getInfo(PluginCall call) {
        try {
            PackageManager pm = getContext().getPackageManager();
            PackageInfo info = pm.getPackageInfo(getContext().getPackageName(), 0);

            long versionCode;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                versionCode = info.getLongVersionCode();
            } else {
                versionCode = info.versionCode;
            }

            JSObject result = new JSObject();
            result.put("version", info.versionName);
            result.put("build", versionCode);
            result.put("packageName", getContext().getPackageName());
            result.put("canInstall", hasInstallPermission());
            call.resolve(result);
        } catch (PackageManager.NameNotFoundException e) {
            call.reject("Could not read package info", e);
        }
    }

    @PluginMethod
    public void canInstallPackages(PluginCall call) {
        JSObject result = new JSObject();
        result.put("granted", hasInstallPermission());
        call.resolve(result);
    }

    /**
     * Opens the system screen where the user allows this app to install
     * packages. Required once on Android 8 and above.
     */
    @PluginMethod
    public void openInstallPermissionSettings(PluginCall call) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent intent = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES)
                .setData(Uri.parse("package:" + getContext().getPackageName()))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            getContext().startActivity(intent);
        }
        call.resolve();
    }

    @PluginMethod
    public void downloadAndInstall(final PluginCall call) {
        final String url = call.getString("url");

        if (url == null || url.isEmpty()) {
            call.reject("No download URL supplied");
            return;
        }
        if (!isAllowedUrl(url)) {
            call.reject("Refusing to download from an untrusted host");
            return;
        }
        if (!hasInstallPermission()) {
            call.reject("Install permission has not been granted");
            return;
        }

        // Networking must not run on the UI thread.
        new Thread(() -> {
            try {
                File apk = download(url, call);
                launchInstaller(apk);

                JSObject result = new JSObject();
                result.put("installed", true);
                result.put("path", apk.getAbsolutePath());
                call.resolve(result);
            } catch (Exception e) {
                call.reject(e.getMessage() != null ? e.getMessage() : "Download failed", e);
            }
        }, "ciphervault-update").start();
    }

    // ------------------------------------------------------------- internals

    private boolean hasInstallPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return true;
        return getContext().getPackageManager().canRequestPackageInstalls();
    }

    private boolean isAllowedUrl(String rawUrl) {
        try {
            URL parsed = new URL(rawUrl);
            if (!"https".equalsIgnoreCase(parsed.getProtocol())) return false;
            String host = parsed.getHost().toLowerCase(Locale.ROOT);
            return ALLOWED_HOSTS.contains(host);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Streams the APK into app-private external storage, emitting progress.
     *
     * Redirects are followed manually because HttpURLConnection will not carry
     * them across hosts automatically in every Android version, and GitHub
     * always redirects release assets to its object storage.
     */
    private File download(String url, PluginCall call) throws IOException {
        File dir = new File(getContext().getExternalFilesDir(null), "updates");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new IOException("Could not create the download folder");
        }

        // A stale part-file from a previous failed attempt must never be installed.
        File target = new File(dir, "ciphervault-update.apk");
        if (target.exists() && !target.delete()) {
            throw new IOException("Could not clear the previous download");
        }

        String current = url;
        HttpURLConnection connection = null;

        try {
            for (int redirect = 0; ; redirect++) {
                if (redirect > MAX_REDIRECTS) throw new IOException("Too many redirects");
                if (!isAllowedUrl(current)) throw new IOException("Redirected to an untrusted host");

                connection = (HttpURLConnection) new URL(current).openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(READ_TIMEOUT_MS);
                connection.setRequestProperty("Accept", "application/octet-stream");
                connection.connect();

                int status = connection.getResponseCode();
                if (status == HttpURLConnection.HTTP_MOVED_PERM
                    || status == HttpURLConnection.HTTP_MOVED_TEMP
                    || status == HttpURLConnection.HTTP_SEE_OTHER
                    || status == 307
                    || status == 308) {
                    String location = connection.getHeaderField("Location");
                    connection.disconnect();
                    if (location == null) throw new IOException("Redirect without a location");
                    current = new URL(new URL(current), location).toString();
                    continue;
                }

                if (status != HttpURLConnection.HTTP_OK) {
                    throw new IOException("Server returned HTTP " + status);
                }
                break;
            }

            long total = connection.getContentLength();
            long written = 0;
            int lastPercent = -1;

            try (InputStream in = connection.getInputStream();
                 FileOutputStream out = new FileOutputStream(target)) {

                byte[] buffer = new byte[16 * 1024];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                    written += read;

                    if (total > 0) {
                        int percent = (int) ((written * 100) / total);
                        if (percent != lastPercent) {
                            lastPercent = percent;
                            JSObject progress = new JSObject();
                            progress.put("percent", percent);
                            progress.put("bytes", written);
                            progress.put("total", total);
                            notifyListeners("downloadProgress", progress);
                        }
                    }
                }
                out.flush();
            }

            if (total > 0 && written != total) {
                // A truncated APK would fail to install with a confusing error.
                if (!target.delete()) target.deleteOnExit();
                throw new IOException("Download incomplete - check your connection and try again");
            }

            return target;
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    /**
     * Hands the APK to Android's package installer. The system verifies the
     * signature: an update signed with a different key than the installed app
     * is rejected here, not by us.
     */
    private void launchInstaller(File apk) {
        Uri uri = FileProvider.getUriForFile(
            getContext(),
            getContext().getPackageName() + ".fileprovider",
            apk
        );

        Intent intent = new Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);

        getContext().startActivity(intent);
    }
}
