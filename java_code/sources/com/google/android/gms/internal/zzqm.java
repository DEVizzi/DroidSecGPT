package com.google.android.gms.internal;

import android.os.Build;
/* loaded from: classes.dex */
public class zzqm {
    public zzql zzAG() {
        return zzyj() < 8 ? new zzqj() : new zzqk();
    }

    int zzyj() {
        return Build.VERSION.SDK_INT;
    }
}
