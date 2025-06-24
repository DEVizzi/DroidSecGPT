package com.google.android.gms.internal;

import android.util.Base64;
/* loaded from: classes.dex */
public final class zzky {
    public static String zzi(byte[] bArr) {
        if (bArr == null) {
            return null;
        }
        return Base64.encodeToString(bArr, 0);
    }

    public static String zzj(byte[] bArr) {
        if (bArr == null) {
            return null;
        }
        return Base64.encodeToString(bArr, 10);
    }
}
