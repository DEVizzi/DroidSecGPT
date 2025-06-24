package com.google.android.gms.internal;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.util.Log;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public final class zzog implements Application.ActivityLifecycleCallbacks {
    private final zznw zzaEV;
    private final Map<Activity, zzod> zzaEW;

    public zzog(zznw zznwVar) {
        com.google.android.gms.common.internal.zzu.zzu(zznwVar);
        this.zzaEV = zznwVar;
        this.zzaEW = new HashMap();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityCreated(Activity activity, Bundle savedInstanceState) {
        Bundle bundle;
        if (savedInstanceState == null || (bundle = savedInstanceState.getBundle("com.google.android.gms.measurement.screen_view")) == null) {
            return;
        }
        int i = bundle.getInt("id");
        if (i <= 0) {
            Log.w("com.google.android.gms.measurement.internal.ActivityLifecycleTracker", "Invalid screenId in saved activity state");
            return;
        }
        zzod zza = zza(activity, i);
        zza.setScreenName(bundle.getString("name"));
        zza.zzhL(bundle.getInt("referrer_id"));
        zza.zzdJ(bundle.getString("referrer_name"));
        zza.zzai(bundle.getBoolean("interstitial"));
        zza.zzwF();
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityDestroyed(Activity activity) {
        this.zzaEW.remove(activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityPaused(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityResumed(Activity activity) {
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivitySaveInstanceState(Activity activity, Bundle outState) {
        zzod zzodVar;
        if (outState == null || (zzodVar = this.zzaEW.get(activity)) == null) {
            return;
        }
        Bundle bundle = new Bundle();
        bundle.putInt("id", zzodVar.zzbn());
        bundle.putString("name", zzodVar.zzwB());
        bundle.putInt("referrer_id", zzodVar.zzwC());
        bundle.putString("referrer_name", zzodVar.zzwD());
        bundle.putBoolean("interstitial", zzodVar.zzwG());
        outState.putBundle("com.google.android.gms.measurement.screen_view", bundle);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStarted(Activity activity) {
        this.zzaEV.zzb(zza(activity, 0), activity);
    }

    @Override // android.app.Application.ActivityLifecycleCallbacks
    public void onActivityStopped(Activity activity) {
    }

    zzod zza(Activity activity, int i) {
        com.google.android.gms.common.internal.zzu.zzu(activity);
        zzod zzodVar = this.zzaEW.get(activity);
        if (zzodVar == null) {
            zzodVar = i == 0 ? new zzod(true) : new zzod(true, i);
            zzodVar.setScreenName(activity.getClass().getCanonicalName());
            this.zzaEW.put(activity, zzodVar);
        }
        return zzodVar;
    }
}
