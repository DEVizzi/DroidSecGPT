package com.google.android.gms.games.internal;

import com.google.android.gms.common.internal.zzn;
/* loaded from: classes.dex */
public final class GamesLog {
    private static final zzn zzaft = new zzn("Games");

    private GamesLog() {
    }

    public static void zza(String str, String str2, Throwable th) {
        zzaft.zza(str, str2, th);
    }

    public static void zzb(String str, String str2, Throwable th) {
        zzaft.zzb(str, str2, th);
    }

    public static void zzu(String str, String str2) {
        zzaft.zzu(str, str2);
    }

    public static void zzv(String str, String str2) {
        zzaft.zzv(str, str2);
    }
}
