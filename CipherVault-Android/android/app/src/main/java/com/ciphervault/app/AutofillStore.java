package com.ciphervault.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * The credential cache the autofill service reads from.
 *
 * The vault itself lives encrypted inside the WebView, keyed by the master
 * password, and native code cannot reach it. But Android's AutofillService runs
 * without the app open, so it needs its own copy of just the logins.
 *
 * Design: hybrid RSA + AES, so that *writing* the cache never needs
 * authentication but *reading* it always does.
 *
 *   - An RSA key pair lives in the AndroidKeyStore. The private key is marked
 *     setUserAuthenticationRequired(true) with a short validity window, so it
 *     only works just after a biometric or device-credential prompt.
 *   - save() (called from the unlocked app) generates a fresh random AES key,
 *     AES-GCM encrypts the logins with it, and RSA-wraps that AES key with the
 *     PUBLIC key. Public-key encryption needs no authentication, so the app can
 *     refresh the cache freely whenever the vault changes.
 *   - load() (called by the autofill unlock activity, after a biometric) uses
 *     the PRIVATE key to unwrap the AES key, then decrypts the logins.
 *
 * A symmetric auth-bound key was the obvious first choice, but AndroidKeyStore
 * gates such keys on authentication for *encryption as well as decryption*,
 * which would make cache writes fail unpredictably. The asymmetric split is the
 * standard way around that.
 *
 * At rest the file is: an RSA-wrapped AES key, an IV, and AES-GCM ciphertext.
 * None of it is readable without passing the biometric prompt.
 */
final class AutofillStore {

    private static final String KEY_ALIAS = "ciphervault_autofill_rsa";
    private static final String KEYSTORE = "AndroidKeyStore";

    private static final String RSA_TRANSFORM = "RSA/ECB/PKCS1Padding";
    private static final String AES_TRANSFORM = "AES/GCM/NoPadding";

    private static final String PREFS = "ciphervault_autofill";
    private static final String PREF_WRAPPED_KEY = "wrappedKey";
    private static final String PREF_IV = "iv";
    private static final String PREF_PAYLOAD = "payload";
    private static final String PREF_COUNT = "count";

    /** How long after an authentication the private key stays usable. */
    private static final int AUTH_VALIDITY_SECONDS = 30;

    // Instrumented tests set this so the key pair can be created without the
    // biometric requirement, letting the crypto round-trip be checked
    // unattended. Never set in production code.
    private static boolean sTestModeNoAuth = false;

    static void setTestModeNoAuth(boolean on) { sTestModeNoAuth = on; }

    private AutofillStore() {}

    static final class Credential {
        final String title;
        final String username;
        final String password;
        final String url;

        Credential(String title, String username, String password, String url) {
            this.title = title;
            this.username = username;
            this.password = password;
            this.url = url;
        }
    }

    private static SharedPreferences prefs(Context ctx) {
        return ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    static boolean hasCredentials(Context ctx) {
        return prefs(ctx).contains(PREF_PAYLOAD);
    }

    /** Number of cached logins. Safe to read without authenticating. */
    static int count(Context ctx) {
        return prefs(ctx).getInt(PREF_COUNT, 0);
    }

    static void clear(Context ctx) {
        prefs(ctx).edit()
            .remove(PREF_WRAPPED_KEY)
            .remove(PREF_IV)
            .remove(PREF_PAYLOAD)
            .remove(PREF_COUNT)
            .apply();
    }

    /** Drops the cache and destroys the key pair it was encrypted under. */
    static void wipe(Context ctx) {
        clear(ctx);
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS);
        } catch (Exception ignored) {
            // Next save regenerates it.
        }
    }

    /**
     * Replaces the cache. Called from the unlocked app whenever the vault
     * changes. Requires no user authentication - encryption uses the public
     * key.
     */
    static void save(Context ctx, JSONArray logins) throws Exception {
        PublicKey publicKey = loadOrCreateKeyPair(ctx);

        byte[] plaintext = logins.toString().getBytes(StandardCharsets.UTF_8);

        // Fresh AES key per write.
        KeyGenerator aesGen = KeyGenerator.getInstance("AES");
        aesGen.init(256);
        SecretKey aesKey = aesGen.generateKey();

        Cipher aes = Cipher.getInstance(AES_TRANSFORM);
        aes.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] ciphertext = aes.doFinal(plaintext);
        byte[] iv = aes.getIV();

        Cipher rsa = Cipher.getInstance(RSA_TRANSFORM);
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());

        prefs(ctx).edit()
            .putString(PREF_WRAPPED_KEY, Base64.encodeToString(wrappedKey, Base64.NO_WRAP))
            .putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(PREF_PAYLOAD, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .putInt(PREF_COUNT, logins.length())
            .apply();
    }

    /**
     * Decrypts the cache. The RSA unwrap uses the auth-bound private key, so
     * this only succeeds within the authentication window - callers must have
     * just completed a biometric or device-credential prompt.
     */
    static List<Credential> load(Context ctx) throws Exception {
        SharedPreferences p = prefs(ctx);
        String wrapped = p.getString(PREF_WRAPPED_KEY, null);
        String ivStr = p.getString(PREF_IV, null);
        String payload = p.getString(PREF_PAYLOAD, null);
        if (wrapped == null || ivStr == null || payload == null) return new ArrayList<>();

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, null);
        if (privateKey == null) throw new IllegalStateException("Autofill key is gone");

        Cipher rsa = Cipher.getInstance(RSA_TRANSFORM);
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsa.doFinal(Base64.decode(wrapped, Base64.NO_WRAP));
        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");

        Cipher aes = Cipher.getInstance(AES_TRANSFORM);
        aes.init(Cipher.DECRYPT_MODE, aesKey,
            new GCMParameterSpec(128, Base64.decode(ivStr, Base64.NO_WRAP)));
        byte[] plain = aes.doFinal(Base64.decode(payload, Base64.NO_WRAP));

        JSONArray arr = new JSONArray(new String(plain, StandardCharsets.UTF_8));
        List<Credential> out = new ArrayList<>();
        for (int i = 0; i < arr.length(); i++) {
            JSONObject o = arr.getJSONObject(i);
            out.add(new Credential(
                o.optString("title", ""),
                o.optString("username", ""),
                o.optString("password", ""),
                o.optString("url", "")
            ));
        }
        return out;
    }

    /** @return the public half, creating the pair on first use. */
    private static PublicKey loadOrCreateKeyPair(Context ctx) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);

        if (keyStore.containsAlias(KEY_ALIAS)) {
            return keyStore.getCertificate(KEY_ALIAS).getPublicKey();
        }

        KeyPairGenerator generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(2048)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            // Only the private (decrypt) half is gated; the public half is not.
            .setUserAuthenticationRequired(!sTestModeNoAuth);

        if (sTestModeNoAuth) {
            generator.initialize(builder.build());
            return generator.generateKeyPair().getPublic();
        }

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                AUTH_VALIDITY_SECONDS,
                KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS);
        }

        generator.initialize(builder.build());
        return generator.generateKeyPair().getPublic();
    }
}
