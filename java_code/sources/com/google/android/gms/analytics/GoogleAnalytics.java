package com.google.android.gms.analytics;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import com.google.android.gms.analytics.internal.zzae;
import com.google.android.gms.analytics.internal.zzak;
import com.google.android.gms.analytics.internal.zzal;
import com.google.android.gms.analytics.internal.zzan;
import com.google.android.gms.analytics.internal.zzf;
import com.google.android.gms.analytics.internal.zzy;
import com.google.android.gms.common.internal.zzu;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public final class GoogleAnalytics extends com.google.android.gms.analytics.zza {
    private static List<Runnable> zzIt = new ArrayList();
    private boolean zzIu;
    private Set<zza> zzIv;
    private boolean zzIw;
    private boolean zzIx;
    private volatile boolean zzIy;
    private boolean zzIz;
    private boolean zzpb;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zza {
        void zzn(Activity activity);

        void zzo(Activity activity);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class zzb implements Application.ActivityLifecycleCallbacks {
        zzb() {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityDestroyed(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityPaused(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityResumed(Activity activity) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStarted(Activity activity) {
            GoogleAnalytics.this.zzl(activity);
        }

        @Override // android.app.Application.ActivityLifecycleCallbacks
        public void onActivityStopped(Activity activity) {
            GoogleAnalytics.this.zzm(activity);
        }
    }

    public GoogleAnalytics(zzf context) {
        super(context);
        this.zzIv = new HashSet();
    }

    public static GoogleAnalytics getInstance(Context context) {
        return zzf.zzV(context).zzie();
    }

    public static void zzhj() {
        synchronized (GoogleAnalytics.class) {
            if (zzIt != null) {
                for (Runnable runnable : zzIt) {
                    runnable.run();
                }
                zzIt = null;
            }
        }
    }

    private com.google.android.gms.analytics.internal.zzb zzhl() {
        return zzhb().zzhl();
    }

    private zzan zzhm() {
        return zzhb().zzhm();
    }

    public void dispatchLocalHits() {
        zzhl().zzhH();
    }

    public void enableAutoActivityReports(Application application) {
        if (Build.VERSION.SDK_INT < 14 || this.zzIw) {
            return;
        }
        application.registerActivityLifecycleCallbacks(new zzb());
        this.zzIw = true;
    }

    public boolean getAppOptOut() {
        return this.zzIy;
    }

    public String getClientId() {
        zzu.zzbZ("getClientId can not be called from the main thread");
        return zzhb().zzih().zziP();
    }

    @Deprecated
    public Logger getLogger() {
        return zzae.getLogger();
    }

    public boolean isDryRunEnabled() {
        return this.zzIx;
    }

    public boolean isInitialized() {
        return this.zzpb && !this.zzIu;
    }

    public Tracker newTracker(int configResId) {
        Tracker tracker;
        zzal zzab;
        synchronized (this) {
            tracker = new Tracker(zzhb(), null, null);
            if (configResId > 0 && (zzab = new zzak(zzhb()).zzab(configResId)) != null) {
                tracker.zza(zzab);
            }
            tracker.zza();
        }
        return tracker;
    }

    public Tracker newTracker(String trackingId) {
        Tracker tracker;
        synchronized (this) {
            tracker = new Tracker(zzhb(), trackingId, null);
            tracker.zza();
        }
        return tracker;
    }

    public void reportActivityStart(Activity activity) {
        if (this.zzIw) {
            return;
        }
        zzl(activity);
    }

    public void reportActivityStop(Activity activity) {
        if (this.zzIw) {
            return;
        }
        zzm(activity);
    }

    public void setAppOptOut(boolean optOut) {
        this.zzIy = optOut;
        if (this.zzIy) {
            zzhl().zzhG();
        }
    }

    public void setDryRun(boolean dryRun) {
        this.zzIx = dryRun;
    }

    public void setLocalDispatchPeriod(int dispatchPeriodInSeconds) {
        zzhl().setLocalDispatchPeriod(dispatchPeriodInSeconds);
    }

    @Deprecated
    public void setLogger(Logger logger) {
        zzae.setLogger(logger);
        if (this.zzIz) {
            return;
        }
        Log.i(zzy.zzLb.get(), "GoogleAnalytics.setLogger() is deprecated. To enable debug logging, please run:\nadb shell setprop log.tag." + zzy.zzLb.get() + " DEBUG");
        this.zzIz = true;
    }

    public void zza() {
        zzhi();
        this.zzpb = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(zza zzaVar) {
        this.zzIv.add(zzaVar);
        Context context = zzhb().getContext();
        if (context instanceof Application) {
            enableAutoActivityReports((Application) context);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzb(zza zzaVar) {
        this.zzIv.remove(zzaVar);
    }

    void zzhi() {
        Logger logger;
        zzan zzhm = zzhm();
        if (zzhm.zzjO()) {
            getLogger().setLogLevel(zzhm.getLogLevel());
        }
        if (zzhm.zzjS()) {
            setDryRun(zzhm.zzjT());
        }
        if (!zzhm.zzjO() || (logger = zzae.getLogger()) == null) {
            return;
        }
        logger.setLogLevel(zzhm.getLogLevel());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzhk() {
        zzhl().zzhI();
    }

    void zzl(Activity activity) {
        for (zza zzaVar : this.zzIv) {
            zzaVar.zzn(activity);
        }
    }

    void zzm(Activity activity) {
        for (zza zzaVar : this.zzIv) {
            zzaVar.zzo(activity);
        }
    }
}
