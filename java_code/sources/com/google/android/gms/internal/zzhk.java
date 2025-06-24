package com.google.android.gms.internal;

import android.os.Process;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
@zzgd
/* loaded from: classes.dex */
public final class zzhk {
    private static final ExecutorService zzGe = Executors.newFixedThreadPool(10, zzas("Default"));
    private static final ExecutorService zzGf = Executors.newFixedThreadPool(5, zzas("Loader"));

    public static zzhv<Void> zza(int i, final Runnable runnable) {
        return i == 1 ? zza(zzGf, new Callable<Void>() { // from class: com.google.android.gms.internal.zzhk.1
            @Override // java.util.concurrent.Callable
            /* renamed from: zzgk */
            public Void call() {
                runnable.run();
                return null;
            }
        }) : zza(zzGe, new Callable<Void>() { // from class: com.google.android.gms.internal.zzhk.2
            @Override // java.util.concurrent.Callable
            /* renamed from: zzgk */
            public Void call() {
                runnable.run();
                return null;
            }
        });
    }

    public static zzhv<Void> zza(Runnable runnable) {
        return zza(0, runnable);
    }

    public static <T> zzhv<T> zza(Callable<T> callable) {
        return zza(zzGe, callable);
    }

    public static <T> zzhv<T> zza(ExecutorService executorService, final Callable<T> callable) {
        final zzhs zzhsVar = new zzhs();
        try {
            executorService.submit(new Runnable() { // from class: com.google.android.gms.internal.zzhk.3
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        Process.setThreadPriority(10);
                        zzhs.this.zzf(callable.call());
                    } catch (Exception e) {
                        com.google.android.gms.ads.internal.zzo.zzby().zzc((Throwable) e, true);
                        zzhs.this.cancel(true);
                    }
                }
            });
        } catch (RejectedExecutionException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Thread execution is rejected.", e);
            zzhsVar.cancel(true);
        }
        return zzhsVar;
    }

    private static ThreadFactory zzas(final String str) {
        return new ThreadFactory() { // from class: com.google.android.gms.internal.zzhk.4
            private final AtomicInteger zzGi = new AtomicInteger(1);

            @Override // java.util.concurrent.ThreadFactory
            public Thread newThread(Runnable runnable) {
                return new Thread(runnable, "AdWorker(" + str + ") #" + this.zzGi.getAndIncrement());
            }
        };
    }
}
