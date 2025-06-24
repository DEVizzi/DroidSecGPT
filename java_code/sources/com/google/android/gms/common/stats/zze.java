package com.google.android.gms.common.stats;

import android.os.SystemClock;
import android.support.v4.util.SimpleArrayMap;
import android.util.Log;
/* loaded from: classes.dex */
public class zze {
    private final long zzacG;
    private final int zzacH;
    private final SimpleArrayMap<String, Long> zzacI;

    public zze() {
        this.zzacG = 60000L;
        this.zzacH = 10;
        this.zzacI = new SimpleArrayMap<>(10);
    }

    public zze(int i, long j) {
        this.zzacG = j;
        this.zzacH = i;
        this.zzacI = new SimpleArrayMap<>();
    }

    private void zzc(long j, long j2) {
        for (int size = this.zzacI.size() - 1; size >= 0; size--) {
            if (j2 - this.zzacI.valueAt(size).longValue() > j) {
                this.zzacI.removeAt(size);
            }
        }
    }

    public Long zzcp(String str) {
        Long put;
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long j = this.zzacG;
        synchronized (this) {
            while (this.zzacI.size() >= this.zzacH) {
                zzc(j, elapsedRealtime);
                j /= 2;
                Log.w("ConnectionTracker", "The max capacity " + this.zzacH + " is not enough. Current durationThreshold is: " + j);
            }
            put = this.zzacI.put(str, Long.valueOf(elapsedRealtime));
        }
        return put;
    }

    public boolean zzcq(String str) {
        boolean z;
        synchronized (this) {
            z = this.zzacI.remove(str) != null;
        }
        return z;
    }
}
