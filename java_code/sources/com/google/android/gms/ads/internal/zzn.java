package com.google.android.gms.ads.internal;

import android.os.Handler;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzhl;
import java.lang.ref.WeakReference;
@zzgd
/* loaded from: classes.dex */
public class zzn {
    private final zza zzpg;
    private AdRequestParcel zzph;
    private boolean zzpi;
    private boolean zzpj;
    private long zzpk;
    private final Runnable zzx;

    /* loaded from: classes.dex */
    public static class zza {
        private final Handler mHandler;

        public zza(Handler handler) {
            this.mHandler = handler;
        }

        public boolean postDelayed(Runnable runnable, long timeFromNowInMillis) {
            return this.mHandler.postDelayed(runnable, timeFromNowInMillis);
        }

        public void removeCallbacks(Runnable runnable) {
            this.mHandler.removeCallbacks(runnable);
        }
    }

    public zzn(com.google.android.gms.ads.internal.zza zzaVar) {
        this(zzaVar, new zza(zzhl.zzGk));
    }

    zzn(com.google.android.gms.ads.internal.zza zzaVar, zza zzaVar2) {
        this.zzpi = false;
        this.zzpj = false;
        this.zzpk = 0L;
        this.zzpg = zzaVar2;
        final WeakReference weakReference = new WeakReference(zzaVar);
        this.zzx = new Runnable() { // from class: com.google.android.gms.ads.internal.zzn.1
            @Override // java.lang.Runnable
            public void run() {
                zzn.this.zzpi = false;
                com.google.android.gms.ads.internal.zza zzaVar3 = (com.google.android.gms.ads.internal.zza) weakReference.get();
                if (zzaVar3 != null) {
                    zzaVar3.zzd(zzn.this.zzph);
                }
            }
        };
    }

    public void cancel() {
        this.zzpi = false;
        this.zzpg.removeCallbacks(this.zzx);
    }

    public void pause() {
        this.zzpj = true;
        if (this.zzpi) {
            this.zzpg.removeCallbacks(this.zzx);
        }
    }

    public void resume() {
        this.zzpj = false;
        if (this.zzpi) {
            this.zzpi = false;
            zza(this.zzph, this.zzpk);
        }
    }

    public void zza(AdRequestParcel adRequestParcel, long j) {
        if (this.zzpi) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("An ad refresh is already scheduled.");
            return;
        }
        this.zzph = adRequestParcel;
        this.zzpi = true;
        this.zzpk = j;
        if (this.zzpj) {
            return;
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzaA("Scheduling ad refresh " + j + " milliseconds from now.");
        this.zzpg.postDelayed(this.zzx, j);
    }

    public boolean zzbp() {
        return this.zzpi;
    }

    public void zzf(AdRequestParcel adRequestParcel) {
        zza(adRequestParcel, 60000L);
    }
}
