package com.google.android.gms.internal;

import android.content.Context;
import java.util.regex.Pattern;
/* loaded from: classes.dex */
public final class zzkz {
    private static Pattern zzacJ = null;

    public static boolean zzai(Context context) {
        return context.getPackageManager().hasSystemFeature("android.hardware.type.watch");
    }

    public static int zzbN(int i) {
        return i / 1000;
    }

    public static int zzbO(int i) {
        return (i % 1000) / 100;
    }

    public static boolean zzbP(int i) {
        return zzbO(i) == 3;
    }
}
