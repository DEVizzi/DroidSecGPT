package com.google.android.gms.analytics.internal;
/* loaded from: classes.dex */
public enum zzo {
    NONE,
    GZIP;

    public static zzo zzbd(String str) {
        return "GZIP".equalsIgnoreCase(str) ? GZIP : NONE;
    }
}
