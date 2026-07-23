package com.ciphervault.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Base64;

import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.concurrent.Executor;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;

import androidx.core.content.ContextCompat;

/**
 * Biometric unlock for the vault.
 *
 * The master password is NOT stored anywhere readable. It is sealed with an
 * AES key that lives in the AndroidKeyStore, is marked
 * setUserAuthenticationRequired(true), and therefore physically cannot be used
 * to decrypt anything until the user has passed a biometric prompt. Only the
 * resulting ciphertext and IV go into SharedPreferences; on their own they are
 * useless, even to somebody with root.
 *
 * setInvalidatedByBiometricEnrollment(true) means the key is destroyed the
 * moment a new fingerprint or face is enrolled on the device. Someone adding
 * their own fingerprint to an unlocked phone must not thereby gain access to
 * the vault - in that case the stored secret is dropped and the master
 * password is required again.
 */
@CapacitorPlugin(name = "BiometricAuth")
public class BiometricPlugin extends Plugin {

    private static final String KEY_ALIAS = "ciphervault_biometric_key";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION =
        KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;

    private static final String PREFS = "ciphervault_biometric";
    private static final String PREF_PAYLOAD = "payload";
    private static final String PREF_IV = "iv";

    private static final int AUTHENTICATORS = BiometricManager.Authenticators.BIOMETRIC_STRONG;

    // ------------------------------------------------------------ status

    /** Whether this device can do biometrics, and whether we already hold a secret. */
    @PluginMethod
    public void isAvailable(PluginCall call) {
        BiometricManager manager = BiometricManager.from(getContext());
        int status = manager.canAuthenticate(AUTHENTICATORS);

        String reason;
        switch (status) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                reason = "available";
                break;
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                reason = "This device has no biometric hardware.";
                break;
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                reason = "Biometric hardware is unavailable right now.";
                break;
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                reason = "No fingerprint or face is set up on this device yet.";
                break;
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                reason = "A security update is required before biometrics can be used.";
                break;
            default:
                reason = "Biometrics are not available on this device.";
        }

        JSObject result = new JSObject();
        result.put("available", status == BiometricManager.BIOMETRIC_SUCCESS);
        result.put("reason", reason);
        result.put("enrolled", hasStoredSecret());
        call.resolve(result);
    }

    // ------------------------------------------------------------ enrol

    /** Seals `secret` behind a biometric prompt. */
    @PluginMethod
    public void enable(final PluginCall call) {
        final String secret = call.getString("secret");
        if (secret == null || secret.isEmpty()) {
            call.reject("No secret supplied");
            return;
        }

        final Cipher cipher;
        try {
            deleteKey();                       // always start from a fresh key
            SecretKey key = createKey();
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (Exception e) {
            call.reject("Could not prepare the biometric key: " + e.getMessage(), e);
            return;
        }

        prompt(call, cipher, "Confirm it's you", "Turn on biometric unlock for CipherVault", new AuthHandler() {
            @Override
            public void onSuccess(BiometricPrompt.AuthenticationResult result) {
                try {
                    Cipher authorised = result.getCryptoObject().getCipher();
                    byte[] encrypted = authorised.doFinal(secret.getBytes(StandardCharsets.UTF_8));

                    SharedPreferences.Editor editor = prefs().edit();
                    editor.putString(PREF_PAYLOAD, Base64.encodeToString(encrypted, Base64.NO_WRAP));
                    editor.putString(PREF_IV, Base64.encodeToString(authorised.getIV(), Base64.NO_WRAP));
                    editor.apply();

                    JSObject out = new JSObject();
                    out.put("enabled", true);
                    call.resolve(out);
                } catch (Exception e) {
                    clearStored();
                    call.reject("Could not store the secret: " + e.getMessage(), e);
                }
            }
        });
    }

    // ----------------------------------------------------------- unlock

    /** Prompts, then returns the sealed secret. */
    @PluginMethod
    public void unlock(final PluginCall call) {
        if (!hasStoredSecret()) {
            call.reject("Biometric unlock is not set up");
            return;
        }

        final byte[] payload = Base64.decode(prefs().getString(PREF_PAYLOAD, ""), Base64.NO_WRAP);
        final byte[] iv = Base64.decode(prefs().getString(PREF_IV, ""), Base64.NO_WRAP);

        final Cipher cipher;
        try {
            SecretKey key = loadKey();
            if (key == null) {
                clearStored();
                call.reject("BIOMETRIC_INVALIDATED");
                return;
            }
            cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        } catch (KeyPermanentlyInvalidatedException e) {
            // Fingerprints changed since we sealed this. Drop it and make the
            // user prove they know the master password again.
            clearStored();
            deleteKey();
            call.reject("BIOMETRIC_INVALIDATED");
            return;
        } catch (Exception e) {
            call.reject("Could not prepare decryption: " + e.getMessage(), e);
            return;
        }

        prompt(call, cipher, "Unlock CipherVault", "Use your fingerprint or face to unlock your vault", new AuthHandler() {
            @Override
            public void onSuccess(BiometricPrompt.AuthenticationResult result) {
                try {
                    Cipher authorised = result.getCryptoObject().getCipher();
                    byte[] plain = authorised.doFinal(payload);

                    JSObject out = new JSObject();
                    out.put("secret", new String(plain, StandardCharsets.UTF_8));
                    call.resolve(out);
                } catch (Exception e) {
                    call.reject("Could not decrypt the stored secret: " + e.getMessage(), e);
                }
            }
        });
    }

    /** Forgets the sealed secret and destroys the key. */
    @PluginMethod
    public void disable(PluginCall call) {
        clearStored();
        deleteKey();
        JSObject out = new JSObject();
        out.put("enabled", false);
        call.resolve(out);
    }

    // -------------------------------------------------------- internals

    private interface AuthHandler {
        void onSuccess(BiometricPrompt.AuthenticationResult result);
    }

    private void prompt(final PluginCall call, Cipher cipher, String title, String subtitle, final AuthHandler handler) {
        final FragmentActivity activity = (FragmentActivity) getActivity();
        if (activity == null) {
            call.reject("No activity available");
            return;
        }

        final Executor executor = ContextCompat.getMainExecutor(getContext());

        activity.runOnUiThread(() -> {
            BiometricPrompt biometricPrompt = new BiometricPrompt(activity, executor,
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        handler.onSuccess(result);
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        if (errorCode == BiometricPrompt.ERROR_USER_CANCELED
                            || errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                            || errorCode == BiometricPrompt.ERROR_CANCELED) {
                            call.reject("BIOMETRIC_CANCELLED");
                        } else if (errorCode == BiometricPrompt.ERROR_LOCKOUT
                            || errorCode == BiometricPrompt.ERROR_LOCKOUT_PERMANENT) {
                            call.reject("BIOMETRIC_LOCKOUT");
                        } else {
                            call.reject(errString != null ? errString.toString() : "Authentication failed");
                        }
                    }
                    // onAuthenticationFailed (a non-matching finger) is not terminal:
                    // the prompt stays up and lets them try again.
                });

            BiometricPrompt.PromptInfo info = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle(subtitle)
                .setNegativeButtonText("Use master password")
                .setAllowedAuthenticators(AUTHENTICATORS)
                .setConfirmationRequired(false)
                .build();

            biometricPrompt.authenticate(info, new BiometricPrompt.CryptoObject(cipher));
        });
    }

    private SecretKey createKey() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            // The key is unusable without a fresh biometric authentication.
            .setUserAuthenticationRequired(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // Adding a new fingerprint destroys the key, so a third party
            // enrolling their own biometric cannot inherit vault access.
            builder.setInvalidatedByBiometricEnrollment(true);
        }

        generator.init(builder.build());
        return generator.generateKey();
    }

    private SecretKey loadKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
    }

    private void deleteKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
        } catch (Exception ignored) {
            // Nothing useful to do; the next enable() regenerates it anyway.
        }
    }

    private SharedPreferences prefs() {
        return getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private boolean hasStoredSecret() {
        return prefs().contains(PREF_PAYLOAD) && prefs().contains(PREF_IV);
    }

    private void clearStored() {
        prefs().edit().remove(PREF_PAYLOAD).remove(PREF_IV).apply();
    }
}
