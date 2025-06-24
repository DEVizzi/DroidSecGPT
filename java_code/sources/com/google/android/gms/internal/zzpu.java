package com.google.android.gms.internal;

import android.app.Activity;
import android.content.Context;
import android.text.TextUtils;
import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.analytics.HitBuilders;
import com.google.android.gms.analytics.Tracker;
import com.google.android.gms.internal.zznw;
import com.google.android.gms.internal.zzpv;
import com.google.android.gms.tagmanager.Container;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzpu {
    private final Context mContext;
    private final zzpv zzoY;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza implements zznw.zza {
        private final Tracker zzIq;

        zza(Tracker tracker) {
            this.zzIq = tracker;
        }

        @Override // com.google.android.gms.internal.zznw.zza
        public void zza(zzod zzodVar) {
            this.zzIq.setScreenName(zzodVar.zzwB());
            HitBuilders.ScreenViewBuilder screenViewBuilder = new HitBuilders.ScreenViewBuilder();
            screenViewBuilder.set("&a", String.valueOf(zzodVar.zzbn()));
            this.zzIq.send(screenViewBuilder.build());
        }

        @Override // com.google.android.gms.internal.zznw.zza
        public void zza(zzod zzodVar, Activity activity) {
        }
    }

    public zzpu(Context context, Container container, zzpv zzpvVar) {
        this.mContext = context;
        this.zzoY = zza(container, zzpvVar);
        zzzS();
    }

    static zzpv zza(Container container, zzpv zzpvVar) {
        if (container == null || container.isDefault()) {
            return zzpvVar;
        }
        zzpv.zza zzaVar = new zzpv.zza(zzpvVar.zzzT());
        zzaVar.zzeS(container.getString("trackingId")).zzap(container.getBoolean("trackScreenViews")).zzaq(container.getBoolean("collectAdIdentifiers"));
        return zzaVar.zzzW();
    }

    private void zzzS() {
        if (!this.zzoY.zzzU() || TextUtils.isEmpty(this.zzoY.getTrackingId())) {
            return;
        }
        Tracker zzeR = zzeR(this.zzoY.getTrackingId());
        zzeR.enableAdvertisingIdCollection(this.zzoY.zzzV());
        zzb(new zza(zzeR));
    }

    void zzb(zznw.zza zzaVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzaVar);
        zznw zzaC = zznw.zzaC(this.mContext);
        zzaC.zzaf(true);
        zzaC.zza(zzaVar);
    }

    Tracker zzeR(String str) {
        return GoogleAnalytics.getInstance(this.mContext).newTracker(str);
    }

    public zzpv zzzR() {
        return this.zzoY;
    }
}
