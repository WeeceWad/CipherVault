package com.ciphervault.app;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Proves the autofill cache round-trips through the RSA+AES hybrid on a real
 * device keystore. The private key here is created WITHOUT the auth requirement
 * (see the test-only flag) so it can run unattended; production gates it on a
 * biometric. What this verifies is the crypto plumbing itself: write without
 * the private key, read it back correctly, and that nothing is stored in clear.
 */
@RunWith(AndroidJUnit4.class)
public class AutofillStoreTest {

    private Context ctx;

    @Before
    public void setUp() {
        ctx = ApplicationProvider.getApplicationContext();
        AutofillStore.setTestModeNoAuth(true);   // test-only: skip the biometric gate
        AutofillStore.wipe(ctx);
    }

    @Test
    public void writesWithoutAuthAndReadsBack() throws Exception {
        JSONArray logins = new JSONArray();
        logins.put(login("GitHub", "octocat", "hunter2!", "https://github.com"));
        logins.put(login("Reddit", "me@x.com", "p@ss w0rd", "https://reddit.com"));

        // save() must succeed with no authentication (public-key encryption).
        AutofillStore.save(ctx, logins);

        assertTrue(AutofillStore.hasCredentials(ctx));
        assertEquals(2, AutofillStore.count(ctx));

        // The raw SharedPreferences file must not contain any plaintext secret.
        String raw = ctx.getSharedPreferences("ciphervault_autofill", Context.MODE_PRIVATE)
            .getAll().toString();
        assertFalse(raw.contains("hunter2"));
        assertFalse(raw.contains("octocat"));
        assertFalse(raw.contains("github.com"));

        // load() returns them intact.
        List<AutofillStore.Credential> got = AutofillStore.load(ctx);
        assertEquals(2, got.size());
        assertEquals("GitHub", got.get(0).title);
        assertEquals("octocat", got.get(0).username);
        assertEquals("hunter2!", got.get(0).password);
        assertEquals("p@ss w0rd", got.get(1).password);
    }

    @Test
    public void wipeRemovesEverything() throws Exception {
        JSONArray logins = new JSONArray();
        logins.put(login("X", "u", "p", "https://x.com"));
        AutofillStore.save(ctx, logins);
        assertTrue(AutofillStore.hasCredentials(ctx));

        AutofillStore.wipe(ctx);
        assertFalse(AutofillStore.hasCredentials(ctx));
        assertEquals(0, AutofillStore.count(ctx));
    }

    @Test
    public void reSaveReplacesRatherThanAppends() throws Exception {
        JSONArray first = new JSONArray();
        first.put(login("A", "a", "a", "https://a.com"));
        AutofillStore.save(ctx, first);

        JSONArray second = new JSONArray();
        second.put(login("B", "b", "b", "https://b.com"));
        second.put(login("C", "c", "c", "https://c.com"));
        AutofillStore.save(ctx, second);

        assertEquals(2, AutofillStore.count(ctx));
        List<AutofillStore.Credential> got = AutofillStore.load(ctx);
        assertEquals("B", got.get(0).title);
    }

    private JSONObject login(String t, String u, String p, String url) throws Exception {
        JSONObject o = new JSONObject();
        o.put("title", t);
        o.put("username", u);
        o.put("password", p);
        o.put("url", url);
        return o;
    }
}
