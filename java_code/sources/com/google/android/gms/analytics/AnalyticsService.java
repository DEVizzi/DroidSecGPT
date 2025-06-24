package com.google.android.gms.analytics;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.IBinder;
import android.os.PowerManager;
import com.google.android.gms.analytics.internal.zzaf;
import com.google.android.gms.analytics.internal.zzam;
import com.google.android.gms.analytics.internal.zzf;
import com.google.android.gms.analytics.internal.zzw;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class AnalyticsService extends Service {
    private static Boolean zzIe;
    private final Handler mHandler = new Handler();

    public static boolean zzU(Context context) {
        zzu.zzu(context);
        if (zzIe != null) {
            return zzIe.booleanValue();
        }
        boolean zza = zzam.zza(context, AnalyticsService.class);
        zzIe = Boolean.valueOf(zza);
        return zza;
    }

    private void zzhd() {
        try {
            synchronized (AnalyticsReceiver.zzoW) {
                PowerManager.WakeLock wakeLock = AnalyticsReceiver.zzIc;
                if (wakeLock != null && wakeLock.isHeld()) {
                    wakeLock.release();
                }
            }
        } catch (SecurityException e) {
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        zzf zzV = zzf.zzV(this);
        zzaf zzhQ = zzV.zzhQ();
        if (zzV.zzhR().zziW()) {
            zzhQ.zzaT("Device AnalyticsService is starting up");
        } else {
            zzhQ.zzaT("Local AnalyticsService is starting up");
        }
    }

    @Override // android.app.Service
    public void onDestroy() {
        zzf zzV = zzf.zzV(this);
        zzaf zzhQ = zzV.zzhQ();
        if (zzV.zzhR().zziW()) {
            zzhQ.zzaT("Device AnalyticsService is shutting down");
        } else {
            zzhQ.zzaT("Local AnalyticsService is shutting down");
        }
        super.onDestroy();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, final int startId) {
        zzhd();
        final zzf zzV = zzf.zzV(this);
        final zzaf zzhQ = zzV.zzhQ();
        String action = intent.getAction();
        if (zzV.zzhR().zziW()) {
            zzhQ.zza("Device AnalyticsService called. startId, action", Integer.valueOf(startId), action);
        } else {
            zzhQ.zza("Local AnalyticsService called. startId, action", Integer.valueOf(startId), action);
        }
        if ("com.google.android.gms.analytics.ANALYTICS_DISPATCH".equals(action)) {
            zzV.zzhl().zza(new zzw() { // from class: com.google.android.gms.analytics.AnalyticsService.1
                @Override // com.google.android.gms.analytics.internal.zzw
                public void zzc(Throwable th) {
                    AnalyticsService.this.mHandler.post(new Runnable() { // from class: com.google.android.gms.analytics.AnalyticsService.1.1
                        @Override // java.lang.Runnable
                        public void run() {
                            if (AnalyticsService.this.stopSelfResult(startId)) {
                                if (zzV.zzhR().zziW()) {
                                    zzhQ.zzaT("Device AnalyticsService processed last dispatch request");
                                } else {
                                    zzhQ.zzaT("Local AnalyticsService processed last dispatch request");
                                }
                            }
                        }
                    });
                }
            });
        }
        return 2;
    }
}
