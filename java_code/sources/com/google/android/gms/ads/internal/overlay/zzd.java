package com.google.android.gms.ads.internal.overlay;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.support.v4.view.accessibility.AccessibilityEventCompat;
import com.google.android.gms.ads.AdActivity;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.internal.zzlk;
/* loaded from: classes.dex */
public class zzd {
    public void zza(Context context, AdOverlayInfoParcel adOverlayInfoParcel) {
        zza(context, adOverlayInfoParcel, true);
    }

    public void zza(Context context, AdOverlayInfoParcel adOverlayInfoParcel, boolean z) {
        if (adOverlayInfoParcel.zzzK == 4 && adOverlayInfoParcel.zzzD == null) {
            if (adOverlayInfoParcel.zzzC != null) {
                adOverlayInfoParcel.zzzC.onAdClicked();
            }
            zzo.zzbs().zza(context, adOverlayInfoParcel.zzzB, adOverlayInfoParcel.zzzJ);
            return;
        }
        Intent intent = new Intent();
        intent.setClassName(context, AdActivity.CLASS_NAME);
        intent.putExtra("com.google.android.gms.ads.internal.overlay.useClientJar", adOverlayInfoParcel.zzpJ.zzGJ);
        intent.putExtra("shouldCallOnOverlayOpened", z);
        AdOverlayInfoParcel.zza(intent, adOverlayInfoParcel);
        if (!zzlk.isAtLeastL()) {
            intent.addFlags(AccessibilityEventCompat.TYPE_GESTURE_DETECTION_END);
        }
        if (!(context instanceof Activity)) {
            intent.addFlags(DriveFile.MODE_READ_ONLY);
        }
        context.startActivity(intent);
    }
}
