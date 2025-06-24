package com.google.android.gms.ads.internal.util.client;

import android.util.Log;
import com.google.ads.AdRequest;
import com.google.android.gms.internal.zzbz;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class zzb {
    public static boolean zzL(int i) {
        return (i >= 5 || Log.isLoggable(AdRequest.LOGTAG, i)) && (i != 2 || zzgx());
    }

    public static void zza(String str, Throwable th) {
        if (zzL(3)) {
            Log.d(AdRequest.LOGTAG, str, th);
        }
    }

    public static void zzaA(String str) {
        if (zzL(4)) {
            Log.i(AdRequest.LOGTAG, str);
        }
    }

    public static void zzaB(String str) {
        if (zzL(2)) {
            Log.v(AdRequest.LOGTAG, str);
        }
    }

    public static void zzaC(String str) {
        if (zzL(5)) {
            Log.w(AdRequest.LOGTAG, str);
        }
    }

    public static void zzay(String str) {
        if (zzL(3)) {
            Log.d(AdRequest.LOGTAG, str);
        }
    }

    public static void zzaz(String str) {
        if (zzL(6)) {
            Log.e(AdRequest.LOGTAG, str);
        }
    }

    public static void zzb(String str, Throwable th) {
        if (zzL(6)) {
            Log.e(AdRequest.LOGTAG, str, th);
        }
    }

    public static void zzc(String str, Throwable th) {
        if (zzL(4)) {
            Log.i(AdRequest.LOGTAG, str, th);
        }
    }

    public static void zzd(String str, Throwable th) {
        if (zzL(5)) {
            Log.w(AdRequest.LOGTAG, str, th);
        }
    }

    public static boolean zzgx() {
        return zzbz.zzut.get().booleanValue();
    }
}
