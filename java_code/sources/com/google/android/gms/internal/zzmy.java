package com.google.android.gms.internal;

import com.google.android.gms.auth.GoogleAuthUtil;
/* loaded from: classes.dex */
public class zzmy {
    private static final ThreadLocal<String> zzakW = new ThreadLocal<>();

    public static String zzcL(String str) {
        return zzqQ() ? str : zzx(str, zzakW.get());
    }

    public static boolean zzqQ() {
        String str = zzakW.get();
        return str == null || str.startsWith(GoogleAuthUtil.GOOGLE_ACCOUNT_TYPE);
    }

    public static String zzx(String str, String str2) {
        if (str == null || str2 == null) {
            return str;
        }
        byte[] bArr = new byte[str.length() + str2.length()];
        System.arraycopy(str.getBytes(), 0, bArr, 0, str.length());
        System.arraycopy(str2.getBytes(), 0, bArr, str.length(), str2.length());
        return Integer.toHexString(zzlj.zza(bArr, 0, bArr.length, 0));
    }
}
