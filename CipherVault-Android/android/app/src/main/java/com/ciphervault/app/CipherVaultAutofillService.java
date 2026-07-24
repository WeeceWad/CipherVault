package com.ciphervault.app;

import android.app.PendingIntent;
import android.app.assist.AssistStructure;
import android.content.Context;
import android.content.Intent;
import android.content.IntentSender;
import android.os.Build;
import android.os.CancellationSignal;
import android.service.autofill.AutofillService;
import android.service.autofill.FillCallback;
import android.service.autofill.FillRequest;
import android.service.autofill.FillResponse;
import android.service.autofill.SaveCallback;
import android.service.autofill.SaveInfo;
import android.service.autofill.SaveRequest;
import android.text.TextUtils;
import android.view.View;
import android.view.autofill.AutofillId;
import android.widget.RemoteViews;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Lets CipherVault be chosen as Android's password service, so saved logins
 * are offered directly in other apps and in the browser.
 *
 * The credential cache is encrypted behind a key that requires recent user
 * authentication (see AutofillStore), so this service cannot read it on its
 * own. Instead it returns a single "Unlock CipherVault" entry whose
 * authentication intent opens AutofillUnlockActivity; that shows a biometric
 * prompt and only then returns the real datasets. Nothing is revealed until
 * the user proves who they are.
 */
@RequiresApi(api = Build.VERSION_CODES.O)
public class CipherVaultAutofillService extends AutofillService {

    /** Field names that usually mean "username" once lowercased. */
    private static final String[] USERNAME_HINTS = {
        "username", "user_name", "userid", "user_id", "login", "email",
        "e-mail", "emailaddress", "account", "identifier", "phone"
    };

    private static final String[] PASSWORD_HINTS = {
        "password", "passwd", "pwd", "pass", "passphrase"
    };

    /** The fields found in one screen, plus what app or site they belong to. */
    private static final class ParsedForm {
        AutofillId usernameId;
        AutofillId passwordId;
        String webDomain;
        String packageName;

        boolean isUsable() {
            // A password field alone is enough - plenty of sign-in screens ask
            // for the username on a previous page.
            return passwordId != null || usernameId != null;
        }

        List<AutofillId> ids() {
            List<AutofillId> ids = new ArrayList<>();
            if (usernameId != null) ids.add(usernameId);
            if (passwordId != null) ids.add(passwordId);
            return ids;
        }
    }

    @Override
    public void onFillRequest(@NonNull FillRequest request,
                              @NonNull CancellationSignal cancellationSignal,
                              @NonNull FillCallback callback) {
        AssistStructure structure = request.getFillContexts()
            .get(request.getFillContexts().size() - 1)
            .getStructure();

        ParsedForm form = new ParsedForm();
        form.packageName = structure.getActivityComponent() != null
            ? structure.getActivityComponent().getPackageName()
            : null;

        for (int i = 0; i < structure.getWindowNodeCount(); i++) {
            traverse(structure.getWindowNodeAt(i).getRootViewNode(), form);
        }

        // Never offer to fill our own vault.
        if (getPackageName().equals(form.packageName)) {
            callback.onSuccess(null);
            return;
        }

        if (!form.isUsable() || !AutofillStore.hasCredentials(this)) {
            callback.onSuccess(null);
            return;
        }

        int count = AutofillStore.count(this);
        String label = count > 0
            ? "Unlock CipherVault (" + count + " saved)"
            : "Unlock CipherVault";

        RemoteViews presentation = new RemoteViews(getPackageName(), R.layout.autofill_entry);
        presentation.setTextViewText(R.id.autofill_entry_text, label);

        Intent intent = new Intent(this, AutofillUnlockActivity.class);
        intent.putExtra(AutofillUnlockActivity.EXTRA_USERNAME_ID, form.usernameId);
        intent.putExtra(AutofillUnlockActivity.EXTRA_PASSWORD_ID, form.passwordId);
        intent.putExtra(AutofillUnlockActivity.EXTRA_WEB_DOMAIN, form.webDomain);
        intent.putExtra(AutofillUnlockActivity.EXTRA_PACKAGE, form.packageName);

        PendingIntent pending = PendingIntent.getActivity(
            this,
            // A constant request code would let a stale intent be reused with
            // the previous screen's AutofillIds.
            (int) (System.currentTimeMillis() & 0x7FFFFFFF),
            intent,
            PendingIntent.FLAG_CANCEL_CURRENT | PendingIntent.FLAG_MUTABLE);

        IntentSender sender = pending.getIntentSender();

        List<AutofillId> ids = form.ids();
        FillResponse.Builder response = new FillResponse.Builder()
            .setAuthentication(ids.toArray(new AutofillId[0]), sender, presentation);

        // Offer to save new credentials typed by hand.
        if (form.usernameId != null && form.passwordId != null) {
            response.setSaveInfo(new SaveInfo.Builder(
                SaveInfo.SAVE_DATA_TYPE_USERNAME | SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                new AutofillId[]{form.usernameId, form.passwordId}).build());
        } else if (form.passwordId != null) {
            response.setSaveInfo(new SaveInfo.Builder(
                SaveInfo.SAVE_DATA_TYPE_PASSWORD,
                new AutofillId[]{form.passwordId}).build());
        }

        callback.onSuccess(response.build());
    }

    @Override
    public void onSaveRequest(@NonNull SaveRequest request, @NonNull SaveCallback callback) {
        // Writing back into the vault would mean decrypting it out here, which
        // this service deliberately cannot do. Point the user at the app
        // instead of failing silently.
        callback.onFailure("Open CipherVault to save this login.");
    }

    /** Walks the view tree looking for the username and password fields. */
    private void traverse(AssistStructure.ViewNode node, ParsedForm form) {
        if (node == null) return;

        if (!TextUtils.isEmpty(node.getWebDomain()) && form.webDomain == null) {
            form.webDomain = node.getWebDomain();
        }

        if (isFillableField(node)) {
            if (form.passwordId == null && looksLikePassword(node)) {
                form.passwordId = node.getAutofillId();
            } else if (form.usernameId == null && looksLikeUsername(node)) {
                form.usernameId = node.getAutofillId();
            }
        }

        for (int i = 0; i < node.getChildCount(); i++) {
            traverse(node.getChildAt(i), form);
        }
    }

    private boolean isFillableField(AssistStructure.ViewNode node) {
        return node.getAutofillId() != null
            && node.getAutofillType() == View.AUTOFILL_TYPE_TEXT
            && node.getVisibility() == View.VISIBLE;
    }

    private boolean looksLikePassword(AssistStructure.ViewNode node) {
        if (matchesHint(node, View.AUTOFILL_HINT_PASSWORD)) return true;

        int inputType = node.getInputType();
        int variation = inputType & android.text.InputType.TYPE_MASK_VARIATION;
        boolean isTextClass =
            (inputType & android.text.InputType.TYPE_MASK_CLASS) == android.text.InputType.TYPE_CLASS_TEXT;

        if (isTextClass && (
            variation == android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            || variation == android.text.InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            || variation == android.text.InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD)) {
            return true;
        }

        return containsAny(describe(node), PASSWORD_HINTS);
    }

    private boolean looksLikeUsername(AssistStructure.ViewNode node) {
        if (matchesHint(node, View.AUTOFILL_HINT_USERNAME)
            || matchesHint(node, View.AUTOFILL_HINT_EMAIL_ADDRESS)) {
            return true;
        }
        return containsAny(describe(node), USERNAME_HINTS);
    }

    private boolean matchesHint(AssistStructure.ViewNode node, String wanted) {
        String[] hints = node.getAutofillHints();
        if (hints == null) return false;
        for (String h : hints) {
            if (wanted.equalsIgnoreCase(h)) return true;
        }
        return false;
    }

    /** Everything the app told us about this field, lowercased into one string. */
    private String describe(AssistStructure.ViewNode node) {
        StringBuilder sb = new StringBuilder();
        if (node.getIdEntry() != null) sb.append(node.getIdEntry()).append(' ');
        if (node.getHint() != null) sb.append(node.getHint()).append(' ');
        if (node.getContentDescription() != null) sb.append(node.getContentDescription()).append(' ');

        String[] hints = node.getAutofillHints();
        if (hints != null) {
            for (String h : hints) sb.append(h).append(' ');
        }
        return sb.toString().toLowerCase(Locale.ROOT);
    }

    private boolean containsAny(String haystack, String[] needles) {
        for (String n : needles) {
            if (haystack.contains(n)) return true;
        }
        return false;
    }
}
