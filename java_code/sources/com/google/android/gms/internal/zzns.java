package com.google.android.gms.internal;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Process;
import android.text.TextUtils;
import android.util.DisplayMetrics;
import android.util.Log;
import java.lang.Thread;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RunnableFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
/* loaded from: classes.dex */
public final class zzns {
    private static volatile zzns zzaEh;
    private final Context mContext;
    private volatile zznx zzKm;
    private final List<zznt> zzaEi;
    private final zznn zzaEj;
    private final zza zzaEk;
    private Thread.UncaughtExceptionHandler zzaEl;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zza extends ThreadPoolExecutor {
        public zza() {
            super(1, 1, 0L, TimeUnit.MILLISECONDS, new LinkedBlockingQueue());
            setThreadFactory(new zzb());
        }

        @Override // java.util.concurrent.AbstractExecutorService
        protected <T> RunnableFuture<T> newTaskFor(Runnable runnable, T value) {
            return new FutureTask<T>(runnable, value) { // from class: com.google.android.gms.internal.zzns.zza.1
                @Override // java.util.concurrent.FutureTask
                protected void setException(Throwable error) {
                    Thread.UncaughtExceptionHandler uncaughtExceptionHandler = zzns.this.zzaEl;
                    if (uncaughtExceptionHandler != null) {
                        uncaughtExceptionHandler.uncaughtException(Thread.currentThread(), error);
                    } else if (Log.isLoggable("GAv4", 6)) {
                        Log.e("GAv4", "MeasurementExecutor: job failed with " + error);
                    }
                    super.setException(error);
                }
            };
        }
    }

    /* loaded from: classes.dex */
    private static class zzb implements ThreadFactory {
        private static final AtomicInteger zzaEp = new AtomicInteger();

        private zzb() {
        }

        @Override // java.util.concurrent.ThreadFactory
        public Thread newThread(Runnable target) {
            return new zzc(target, "measurement-" + zzaEp.incrementAndGet());
        }
    }

    /* loaded from: classes.dex */
    private static class zzc extends Thread {
        zzc(Runnable runnable, String str) {
            super(runnable, str);
        }

        @Override // java.lang.Thread, java.lang.Runnable
        public void run() {
            Process.setThreadPriority(10);
            super.run();
        }
    }

    zzns(Context context) {
        Context applicationContext = context.getApplicationContext();
        com.google.android.gms.common.internal.zzu.zzu(applicationContext);
        this.mContext = applicationContext;
        this.zzaEk = new zza();
        this.zzaEi = new CopyOnWriteArrayList();
        this.zzaEj = new zznn();
    }

    public static zzns zzaB(Context context) {
        com.google.android.gms.common.internal.zzu.zzu(context);
        if (zzaEh == null) {
            synchronized (zzns.class) {
                if (zzaEh == null) {
                    zzaEh = new zzns(context);
                }
            }
        }
        return zzaEh;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzb(zzno zznoVar) {
        com.google.android.gms.common.internal.zzu.zzbZ("deliver should be called from worker thread");
        com.google.android.gms.common.internal.zzu.zzb(zznoVar.zzvU(), "Measurement must be submitted");
        List<zznu> zzvR = zznoVar.zzvR();
        if (zzvR.isEmpty()) {
            return;
        }
        HashSet hashSet = new HashSet();
        for (zznu zznuVar : zzvR) {
            Uri zzhe = zznuVar.zzhe();
            if (!hashSet.contains(zzhe)) {
                hashSet.add(zzhe);
                zznuVar.zzb(zznoVar);
            }
        }
    }

    public static void zzhO() {
        if (!(Thread.currentThread() instanceof zzc)) {
            throw new IllegalStateException("Call expected from worker thread");
        }
    }

    public Context getContext() {
        return this.mContext;
    }

    public void zza(Thread.UncaughtExceptionHandler uncaughtExceptionHandler) {
        this.zzaEl = uncaughtExceptionHandler;
    }

    public <V> Future<V> zzb(Callable<V> callable) {
        com.google.android.gms.common.internal.zzu.zzu(callable);
        if (Thread.currentThread() instanceof zzc) {
            FutureTask futureTask = new FutureTask(callable);
            futureTask.run();
            return futureTask;
        }
        return this.zzaEk.submit(callable);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zze(zzno zznoVar) {
        if (zznoVar.zzvY()) {
            throw new IllegalStateException("Measurement prototype can't be submitted");
        }
        if (zznoVar.zzvU()) {
            throw new IllegalStateException("Measurement can only be submitted once");
        }
        final zzno zzvP = zznoVar.zzvP();
        zzvP.zzvV();
        this.zzaEk.execute(new Runnable() { // from class: com.google.android.gms.internal.zzns.1
            @Override // java.lang.Runnable
            public void run() {
                zzvP.zzvW().zza(zzvP);
                for (zznt zzntVar : zzns.this.zzaEi) {
                    zzntVar.zza(zzvP);
                }
                zzns.this.zzb(zzvP);
            }
        });
    }

    public void zze(Runnable runnable) {
        com.google.android.gms.common.internal.zzu.zzu(runnable);
        this.zzaEk.submit(runnable);
    }

    public zznx zzwc() {
        if (this.zzKm == null) {
            synchronized (this) {
                if (this.zzKm == null) {
                    zznx zznxVar = new zznx();
                    PackageManager packageManager = this.mContext.getPackageManager();
                    String packageName = this.mContext.getPackageName();
                    zznxVar.setAppId(packageName);
                    zznxVar.setAppInstallerId(packageManager.getInstallerPackageName(packageName));
                    String str = null;
                    try {
                        PackageInfo packageInfo = packageManager.getPackageInfo(this.mContext.getPackageName(), 0);
                        if (packageInfo != null) {
                            CharSequence applicationLabel = packageManager.getApplicationLabel(packageInfo.applicationInfo);
                            if (!TextUtils.isEmpty(applicationLabel)) {
                                packageName = applicationLabel.toString();
                            }
                            str = packageInfo.versionName;
                        }
                    } catch (PackageManager.NameNotFoundException e) {
                        Log.e("GAv4", "Error retrieving package info: appName set to " + packageName);
                    }
                    zznxVar.setAppName(packageName);
                    zznxVar.setAppVersion(str);
                    this.zzKm = zznxVar;
                }
            }
        }
        return this.zzKm;
    }

    public zznz zzwd() {
        DisplayMetrics displayMetrics = this.mContext.getResources().getDisplayMetrics();
        zznz zznzVar = new zznz();
        zznzVar.setLanguage(com.google.android.gms.analytics.internal.zzam.zza(Locale.getDefault()));
        zznzVar.zzhG(displayMetrics.widthPixels);
        zznzVar.zzhH(displayMetrics.heightPixels);
        return zznzVar;
    }
}
