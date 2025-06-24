package com.google.android.gms.cast.internal;

import android.os.SystemClock;
/* loaded from: classes.dex */
public final class zzp {
    private static final zzl zzQW = new zzl("RequestTracker");
    public static final Object zzVr = new Object();
    private long zzVo;
    private zzo zzVq;
    private long zzTM = -1;
    private long zzVp = 0;

    public zzp(long j) {
        this.zzVo = j;
    }

    private void zzmd() {
        this.zzTM = -1L;
        this.zzVq = null;
        this.zzVp = 0L;
    }

    public void clear() {
        synchronized (zzVr) {
            if (this.zzTM != -1) {
                zzmd();
            }
        }
    }

    public boolean zzB(long j) {
        boolean z;
        synchronized (zzVr) {
            z = this.zzTM != -1 && this.zzTM == j;
        }
        return z;
    }

    public void zza(long j, zzo zzoVar) {
        zzo zzoVar2;
        long j2;
        synchronized (zzVr) {
            zzoVar2 = this.zzVq;
            j2 = this.zzTM;
            this.zzTM = j;
            this.zzVq = zzoVar;
            this.zzVp = SystemClock.elapsedRealtime();
        }
        if (zzoVar2 != null) {
            zzoVar2.zzy(j2);
        }
    }

    public boolean zzc(long j, int i) {
        return zzc(j, i, null);
    }

    public boolean zzc(long j, int i, Object obj) {
        boolean z = true;
        zzo zzoVar = null;
        synchronized (zzVr) {
            if (this.zzTM == -1 || this.zzTM != j) {
                z = false;
            } else {
                zzQW.zzb("request %d completed", Long.valueOf(this.zzTM));
                zzoVar = this.zzVq;
                zzmd();
            }
        }
        if (zzoVar != null) {
            zzoVar.zza(j, i, obj);
        }
        return z;
    }

    public boolean zzd(long j, int i) {
        zzo zzoVar;
        boolean z = true;
        long j2 = 0;
        synchronized (zzVr) {
            if (this.zzTM == -1 || j - this.zzVp < this.zzVo) {
                z = false;
                zzoVar = null;
            } else {
                zzQW.zzb("request %d timed out", Long.valueOf(this.zzTM));
                j2 = this.zzTM;
                zzoVar = this.zzVq;
                zzmd();
            }
        }
        if (zzoVar != null) {
            zzoVar.zza(j2, i, null);
        }
        return z;
    }

    public boolean zzme() {
        boolean z;
        synchronized (zzVr) {
            z = this.zzTM != -1;
        }
        return z;
    }
}
