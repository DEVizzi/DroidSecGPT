package com.google.android.gms.internal;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Process;
/* loaded from: classes.dex */
public class zzla {
    public static boolean zzi(Context context, String str) {
        try {
            return (context.getPackageManager().getApplicationInfo(str, 0).flags & 2097152) != 0;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    public static boolean zziW() {
        return com.google.android.gms.common.internal.zzd.zzZR && zzkf.isInitialized() && zzkf.zzmY() == Process.myUid();
    }
}
