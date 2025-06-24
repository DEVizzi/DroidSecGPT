package com.google.android.gms.cast.internal;

import android.text.TextUtils;
import android.util.Log;
import com.google.android.gms.common.internal.zzu;
import java.util.Locale;
/* loaded from: classes.dex */
public class zzl {
    private static boolean zzUT = false;
    protected final String mTag;
    private final boolean zzUU;
    private boolean zzUV;
    private boolean zzUW;
    private String zzUX;

    public zzl(String str) {
        this(str, zzmb());
    }

    public zzl(String str, boolean z) {
        zzu.zzh(str, "The log tag cannot be null or empty.");
        this.mTag = str;
        this.zzUU = str.length() <= 23;
        this.zzUV = z;
        this.zzUW = false;
    }

    public static boolean zzmb() {
        return zzUT;
    }

    public void zzS(boolean z) {
        this.zzUV = z;
    }

    public void zza(String str, Object... objArr) {
        if (zzma()) {
            Log.v(this.mTag, zzg(str, objArr));
        }
    }

    public void zzb(String str, Object... objArr) {
        if (zzlZ() || zzUT) {
            Log.d(this.mTag, zzg(str, objArr));
        }
    }

    public void zzb(Throwable th, String str, Object... objArr) {
        if (zzlZ() || zzUT) {
            Log.d(this.mTag, zzg(str, objArr), th);
        }
    }

    public void zzbJ(String str) {
        this.zzUX = TextUtils.isEmpty(str) ? null : String.format("[%s] ", str);
    }

    public void zzc(String str, Object... objArr) {
        Log.e(this.mTag, zzg(str, objArr));
    }

    public void zzc(Throwable th, String str, Object... objArr) {
        Log.w(this.mTag, zzg(str, objArr), th);
    }

    public void zze(String str, Object... objArr) {
        Log.i(this.mTag, zzg(str, objArr));
    }

    public void zzf(String str, Object... objArr) {
        Log.w(this.mTag, zzg(str, objArr));
    }

    protected String zzg(String str, Object... objArr) {
        if (objArr.length != 0) {
            str = String.format(Locale.ROOT, str, objArr);
        }
        return !TextUtils.isEmpty(this.zzUX) ? this.zzUX + str : str;
    }

    public boolean zzlZ() {
        return this.zzUV || (this.zzUU && Log.isLoggable(this.mTag, 3));
    }

    public boolean zzma() {
        return this.zzUW;
    }
}
