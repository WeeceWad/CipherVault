package com.ciphervault.app;

import android.app.Activity;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.service.autofill.Dataset;
import android.service.autofill.FillResponse;
import android.widget.RemoteViews;
import android.widget.Toast;

import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executor;

/**
 * The biometric gate in front of autofill.
 *
 * Android launches this when the user taps CipherVault in the autofill bar.
 * The credential cache is encrypted with a key that only works just after an
 * authentication, so this shows a prompt, then decrypts, then hands back a
 * dataset per matching login. If the user cancels, nothing is returned and
 * nothing is revealed.
 *
 * Entries are ranked so the ones plausibly belonging to the requesting app or
 * website come first, but every login stays selectable - domain guessing is a
 * hint, not a filter, and hiding a credential the user wanted would be worse
 * than showing a few extras.
 */
@RequiresApi(api = Build.VERSION_CODES.O)
public class AutofillUnlockActivity extends FragmentActivity {

    static final String EXTRA_USERNAME_ID = "cv.usernameId";
    static final String EXTRA_PASSWORD_ID = "cv.passwordId";
    static final String EXTRA_WEB_DOMAIN = "cv.webDomain";
    static final String EXTRA_PACKAGE = "cv.package";

    private AutofillId usernameId;
    private AutofillId passwordId;
    private String webDomain;
    private String callerPackage;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        usernameId = intent.getParcelableExtra(EXTRA_USERNAME_ID);
        passwordId = intent.getParcelableExtra(EXTRA_PASSWORD_ID);
        webDomain = intent.getStringExtra(EXTRA_WEB_DOMAIN);
        callerPackage = intent.getStringExtra(EXTRA_PACKAGE);

        promptForBiometric();
    }

    private void promptForBiometric() {
        BiometricManager manager = BiometricManager.from(this);
        int allowed = BiometricManager.Authenticators.BIOMETRIC_STRONG
            | BiometricManager.Authenticators.DEVICE_CREDENTIAL;

        if (manager.canAuthenticate(allowed) != BiometricManager.BIOMETRIC_SUCCESS) {
            Toast.makeText(this,
                "Set up a screen lock to use CipherVault autofill.",
                Toast.LENGTH_LONG).show();
            finishCancelled();
            return;
        }

        Executor executor = ContextCompat.getMainExecutor(this);

        BiometricPrompt prompt = new BiometricPrompt(this, executor,
            new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                    deliverDatasets();
                }

                @Override
                public void onAuthenticationError(int errorCode, CharSequence errString) {
                    finishCancelled();
                }
            });

        BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
            .setTitle("CipherVault")
            .setSubtitle("Unlock to fill your saved login")
            .setAllowedAuthenticators(allowed)
            .build();

        prompt.authenticate(info);
    }

    private void deliverDatasets() {
        List<AutofillStore.Credential> credentials;
        try {
            credentials = AutofillStore.load(this);
        } catch (Exception e) {
            // Usually means the key was invalidated by a biometric change, or
            // the auth window elapsed. Either way there is nothing to offer.
            Toast.makeText(this,
                "Open CipherVault and unlock it once to refresh autofill.",
                Toast.LENGTH_LONG).show();
            finishCancelled();
            return;
        }

        if (credentials.isEmpty()) {
            finishCancelled();
            return;
        }

        List<AutofillStore.Credential> ordered = rankByRelevance(credentials);

        FillResponse.Builder response = new FillResponse.Builder();
        int added = 0;

        for (AutofillStore.Credential c : ordered) {
            Dataset dataset = buildDataset(c);
            if (dataset != null) {
                response.addDataset(dataset);
                added++;
            }
            // The autofill bar is a small surface; more than this is unusable.
            if (added >= 12) break;
        }

        if (added == 0) {
            finishCancelled();
            return;
        }

        Intent reply = new Intent();
        reply.putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response.build());
        setResult(RESULT_OK, reply);
        finish();
    }

    private Dataset buildDataset(AutofillStore.Credential c) {
        String subtitle = c.username != null && !c.username.isEmpty() ? c.username : c.url;

        RemoteViews presentation = new RemoteViews(getPackageName(), R.layout.autofill_entry);
        presentation.setTextViewText(R.id.autofill_entry_text,
            c.title + (subtitle != null && !subtitle.isEmpty() ? "  ·  " + subtitle : ""));

        Dataset.Builder builder = new Dataset.Builder(presentation);
        boolean any = false;

        if (usernameId != null && c.username != null) {
            builder.setValue(usernameId, AutofillValue.forText(c.username));
            any = true;
        }
        if (passwordId != null && c.password != null) {
            builder.setValue(passwordId, AutofillValue.forText(c.password));
            any = true;
        }

        return any ? builder.build() : null;
    }

    /**
     * Puts likely matches first. Compares the stored URL's host against the
     * requesting web domain, and failing that against the app's package name,
     * which usually contains the company's domain reversed.
     */
    private List<AutofillStore.Credential> rankByRelevance(List<AutofillStore.Credential> all) {
        String target = webDomain != null ? webDomain.toLowerCase(Locale.ROOT) : null;
        String pkg = callerPackage != null ? callerPackage.toLowerCase(Locale.ROOT) : null;

        List<AutofillStore.Credential> strong = new ArrayList<>();
        List<AutofillStore.Credential> weak = new ArrayList<>();

        for (AutofillStore.Credential c : all) {
            String host = hostOf(c.url);
            boolean matches = false;

            if (host != null) {
                if (target != null && (target.endsWith(host) || host.endsWith(target))) {
                    matches = true;
                } else if (pkg != null) {
                    // "com.example.app" contains "example" from example.com
                    String root = host;
                    int dot = root.indexOf('.');
                    if (dot > 0) root = root.substring(0, dot);
                    if (root.length() >= 3 && pkg.contains(root)) matches = true;
                }
            }

            if (matches) strong.add(c);
            else weak.add(c);
        }

        strong.addAll(weak);
        return strong;
    }

    private String hostOf(String url) {
        if (url == null || url.isEmpty()) return null;
        try {
            String withScheme = url.contains("://") ? url : "https://" + url;
            String host = new URI(withScheme).getHost();
            if (host == null) return null;
            host = host.toLowerCase(Locale.ROOT);
            return host.startsWith("www.") ? host.substring(4) : host;
        } catch (Exception e) {
            return null;
        }
    }

    private void finishCancelled() {
        setResult(RESULT_CANCELED);
        finish();
    }
}
