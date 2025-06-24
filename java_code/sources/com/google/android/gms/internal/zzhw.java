package com.google.android.gms.internal;

import java.util.ArrayList;
import java.util.List;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzhw {
    private final Object zzGQ = new Object();
    private final List<Runnable> zzGR = new ArrayList();
    private final List<Runnable> zzGS = new ArrayList();
    private boolean zzGT = false;

    private void zzc(Runnable runnable) {
        zzhk.zza(runnable);
    }

    private void zzd(Runnable runnable) {
        com.google.android.gms.ads.internal.util.client.zza.zzGF.post(runnable);
    }

    public void zzb(Runnable runnable) {
        synchronized (this.zzGQ) {
            if (this.zzGT) {
                zzc(runnable);
            } else {
                this.zzGR.add(runnable);
            }
        }
    }

    public void zzgy() {
        synchronized (this.zzGQ) {
            if (this.zzGT) {
                return;
            }
            for (Runnable runnable : this.zzGR) {
                zzc(runnable);
            }
            for (Runnable runnable2 : this.zzGS) {
                zzd(runnable2);
            }
            this.zzGR.clear();
            this.zzGS.clear();
            this.zzGT = true;
        }
    }
}
