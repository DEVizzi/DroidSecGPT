package com.google.android.gms.internal;

import android.os.Handler;
import java.util.concurrent.Executor;
/* loaded from: classes.dex */
public class zze implements zzn {
    private final Executor zzs;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zza implements Runnable {
        private final zzk zzv;
        private final zzm zzw;
        private final Runnable zzx;

        public zza(zzk zzkVar, zzm zzmVar, Runnable runnable) {
            this.zzv = zzkVar;
            this.zzw = zzmVar;
            this.zzx = runnable;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (this.zzv.isCanceled()) {
                this.zzv.zzd("canceled-at-delivery");
                return;
            }
            if (this.zzw.isSuccess()) {
                this.zzv.zza((zzk) this.zzw.result);
            } else {
                this.zzv.zzc(this.zzw.zzah);
            }
            if (this.zzw.zzai) {
                this.zzv.zzc("intermediate-response");
            } else {
                this.zzv.zzd("done");
            }
            if (this.zzx != null) {
                this.zzx.run();
            }
        }
    }

    public zze(final Handler handler) {
        this.zzs = new Executor() { // from class: com.google.android.gms.internal.zze.1
            @Override // java.util.concurrent.Executor
            public void execute(Runnable command) {
                handler.post(command);
            }
        };
    }

    @Override // com.google.android.gms.internal.zzn
    public void zza(zzk<?> zzkVar, zzm<?> zzmVar) {
        zza(zzkVar, zzmVar, null);
    }

    @Override // com.google.android.gms.internal.zzn
    public void zza(zzk<?> zzkVar, zzm<?> zzmVar, Runnable runnable) {
        zzkVar.zzv();
        zzkVar.zzc("post-response");
        this.zzs.execute(new zza(zzkVar, zzmVar, runnable));
    }

    @Override // com.google.android.gms.internal.zzn
    public void zza(zzk<?> zzkVar, zzr zzrVar) {
        zzkVar.zzc("post-error");
        this.zzs.execute(new zza(zzkVar, zzm.zzd(zzrVar), null));
    }
}
