package com.google.android.gms.internal;

import android.os.Process;
import com.google.android.gms.internal.zzb;
import java.util.concurrent.BlockingQueue;
/* loaded from: classes.dex */
public class zzc extends Thread {
    private static final boolean DEBUG = zzs.DEBUG;
    private final BlockingQueue<zzk<?>> zzh;
    private final BlockingQueue<zzk<?>> zzi;
    private final zzb zzj;
    private final zzn zzk;
    private volatile boolean zzl = false;

    public zzc(BlockingQueue<zzk<?>> blockingQueue, BlockingQueue<zzk<?>> blockingQueue2, zzb zzbVar, zzn zznVar) {
        this.zzh = blockingQueue;
        this.zzi = blockingQueue2;
        this.zzj = zzbVar;
        this.zzk = zznVar;
    }

    public void quit() {
        this.zzl = true;
        interrupt();
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public void run() {
        if (DEBUG) {
            zzs.zza("start new dispatcher", new Object[0]);
        }
        Process.setThreadPriority(10);
        this.zzj.zza();
        while (true) {
            try {
                final zzk<?> take = this.zzh.take();
                take.zzc("cache-queue-take");
                if (take.isCanceled()) {
                    take.zzd("cache-discard-canceled");
                } else {
                    zzb.zza zza = this.zzj.zza(take.zzh());
                    if (zza == null) {
                        take.zzc("cache-miss");
                        this.zzi.put(take);
                    } else if (zza.zzb()) {
                        take.zzc("cache-hit-expired");
                        take.zza(zza);
                        this.zzi.put(take);
                    } else {
                        take.zzc("cache-hit");
                        zzm<?> zza2 = take.zza(new zzi(zza.data, zza.zzg));
                        take.zzc("cache-hit-parsed");
                        if (zza.zzc()) {
                            take.zzc("cache-hit-refresh-needed");
                            take.zza(zza);
                            zza2.zzai = true;
                            this.zzk.zza(take, zza2, new Runnable() { // from class: com.google.android.gms.internal.zzc.1
                                @Override // java.lang.Runnable
                                public void run() {
                                    try {
                                        zzc.this.zzi.put(take);
                                    } catch (InterruptedException e) {
                                    }
                                }
                            });
                        } else {
                            this.zzk.zza(take, zza2);
                        }
                    }
                }
            } catch (InterruptedException e) {
                if (this.zzl) {
                    return;
                }
            }
        }
    }
}
