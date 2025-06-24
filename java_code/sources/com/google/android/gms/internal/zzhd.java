package com.google.android.gms.internal;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v7.media.SystemMediaRouteProvider;
import com.google.android.gms.ads.AdActivity;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
@zzgd
/* loaded from: classes.dex */
public class zzhd {
    final String zzFE;
    long zzFQ = -1;
    long zzFR = -1;
    int zzFS = -1;
    private final Object zzqt = new Object();
    int zzFT = 0;
    int zzFU = 0;

    public zzhd(String str) {
        this.zzFE = str;
    }

    public static boolean zzE(Context context) {
        int identifier = context.getResources().getIdentifier("Theme.Translucent", "style", SystemMediaRouteProvider.PACKAGE_NAME);
        if (identifier == 0) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("Please set theme of AdActivity to @android:style/Theme.Translucent to enable transparent background interstitial ad.");
            return false;
        }
        try {
            if (identifier == context.getPackageManager().getActivityInfo(new ComponentName(context.getPackageName(), AdActivity.CLASS_NAME), 0).theme) {
                return true;
            }
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("Please set theme of AdActivity to @android:style/Theme.Translucent to enable transparent background interstitial ad.");
            return false;
        } catch (PackageManager.NameNotFoundException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to fetch AdActivity theme");
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("Please set theme of AdActivity to @android:style/Theme.Translucent to enable transparent background interstitial ad.");
            return false;
        }
    }

    public void zzb(AdRequestParcel adRequestParcel, long j) {
        synchronized (this.zzqt) {
            if (this.zzFR == -1) {
                this.zzFR = j;
                this.zzFQ = this.zzFR;
            } else {
                this.zzFQ = j;
            }
            if (adRequestParcel.extras == null || adRequestParcel.extras.getInt("gw", 2) != 1) {
                this.zzFS++;
            }
        }
    }

    public Bundle zzd(Context context, String str) {
        Bundle bundle;
        synchronized (this.zzqt) {
            bundle = new Bundle();
            bundle.putString("session_id", this.zzFE);
            bundle.putLong("basets", this.zzFR);
            bundle.putLong("currts", this.zzFQ);
            bundle.putString("seq_num", str);
            bundle.putInt("preqs", this.zzFS);
            bundle.putInt("pclick", this.zzFT);
            bundle.putInt("pimp", this.zzFU);
            bundle.putBoolean("support_transparent_background", zzE(context));
        }
        return bundle;
    }

    public void zzfP() {
        synchronized (this.zzqt) {
            this.zzFU++;
        }
    }

    public void zzfQ() {
        synchronized (this.zzqt) {
            this.zzFT++;
        }
    }

    public long zzgg() {
        return this.zzFR;
    }
}
