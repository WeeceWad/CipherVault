package com.ciphervault.app;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.widget.RemoteViews;

/**
 * Home-screen widget: a single tap target that jumps to the QR unlock scanner.
 *
 * Tapping it deep-links into the app at ciphervault://scan. The app then runs
 * its own biometric unlock (the same flow as the lock screen) and opens the
 * scanner. The widget holds nothing sensitive and needs no permissions - the
 * biometric gate lives in the app, so a stray tap on a locked phone only ever
 * reaches the unlock screen.
 */
public class ScannerWidgetProvider extends AppWidgetProvider {

    @Override
    public void onUpdate(Context context, AppWidgetManager manager, int[] appWidgetIds) {
        for (int id : appWidgetIds) {
            RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.scanner_widget);

            Intent intent = new Intent(context, MainActivity.class)
                .setAction(Intent.ACTION_VIEW)
                .setData(Uri.parse("ciphervault://scan"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);

            PendingIntent pending = PendingIntent.getActivity(
                context,
                0,
                intent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

            views.setOnClickPendingIntent(R.id.scanner_widget_root, pending);
            manager.updateAppWidget(id, views);
        }
    }
}
