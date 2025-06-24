package com.google.android.gms.analytics.internal;

import com.google.android.gms.internal.zzlb;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzaj {
    private long zzMC;
    private final zzlb zzpw;

    public zzaj(zzlb zzlbVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzlbVar);
        this.zzpw = zzlbVar;
    }

    public zzaj(zzlb zzlbVar, long j) {
        com.google.android.gms.common.internal.zzu.zzu(zzlbVar);
        this.zzpw = zzlbVar;
        this.zzMC = j;
    }

    public void clear() {
        this.zzMC = 0L;
    }

    public void start() {
        this.zzMC = this.zzpw.elapsedRealtime();
    }

    public boolean zzv(long j) {
        return this.zzMC == 0 || this.zzpw.elapsedRealtime() - this.zzMC > j;
    }
}
