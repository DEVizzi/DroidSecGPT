package com.google.android.gms.analytics.internal;

import android.app.Application;
import android.content.Context;
import com.google.android.gms.analytics.GoogleAnalytics;
import com.google.android.gms.internal.zzlb;
import com.google.android.gms.internal.zzld;
import com.google.android.gms.internal.zzns;
import java.lang.Thread;
/* loaded from: classes.dex */
public class zzf {
    private static zzf zzJC;
    private final Context mContext;
    private final Context zzJD;
    private final zzr zzJE;
    private final zzaf zzJF;
    private final zzns zzJG;
    private final zzb zzJH;
    private final zzv zzJI;
    private final zzan zzJJ;
    private final zzai zzJK;
    private final GoogleAnalytics zzJL;
    private final zzn zzJM;
    private final zza zzJN;
    private final zzk zzJO;
    private final zzu zzJP;
    private final zzlb zzpw;

    protected zzf(zzg zzgVar) {
        Context applicationContext = zzgVar.getApplicationContext();
        com.google.android.gms.common.internal.zzu.zzb(applicationContext, "Application context can't be null");
        com.google.android.gms.common.internal.zzu.zzb(applicationContext instanceof Application, "getApplicationContext didn't return the application");
        Context zzic = zzgVar.zzic();
        com.google.android.gms.common.internal.zzu.zzu(zzic);
        this.mContext = applicationContext;
        this.zzJD = zzic;
        this.zzpw = zzgVar.zzh(this);
        this.zzJE = zzgVar.zzg(this);
        zzaf zzf = zzgVar.zzf(this);
        zzf.zza();
        this.zzJF = zzf;
        if (zzhR().zziW()) {
            zzhQ().zzaV("Google Analytics " + zze.VERSION + " is starting up.");
        } else {
            zzhQ().zzaV("Google Analytics " + zze.VERSION + " is starting up. To enable debug logging on a device run:\n  adb shell setprop log.tag.GAv4 DEBUG\n  adb logcat -s GAv4");
        }
        zzai zzq = zzgVar.zzq(this);
        zzq.zza();
        this.zzJK = zzq;
        zzan zze = zzgVar.zze(this);
        zze.zza();
        this.zzJJ = zze;
        zzb zzl = zzgVar.zzl(this);
        zzn zzd = zzgVar.zzd(this);
        zza zzc = zzgVar.zzc(this);
        zzk zzb = zzgVar.zzb(this);
        zzu zza = zzgVar.zza(this);
        zzns zzW = zzgVar.zzW(applicationContext);
        zzW.zza(zzib());
        this.zzJG = zzW;
        GoogleAnalytics zzi = zzgVar.zzi(this);
        zzd.zza();
        this.zzJM = zzd;
        zzc.zza();
        this.zzJN = zzc;
        zzb.zza();
        this.zzJO = zzb;
        zza.zza();
        this.zzJP = zza;
        zzv zzp = zzgVar.zzp(this);
        zzp.zza();
        this.zzJI = zzp;
        zzl.zza();
        this.zzJH = zzl;
        if (zzhR().zziW()) {
            zzhQ().zzb("Device AnalyticsService version", zze.VERSION);
        }
        zzi.zza();
        this.zzJL = zzi;
        zzl.start();
    }

    public static zzf zzV(Context context) {
        com.google.android.gms.common.internal.zzu.zzu(context);
        if (zzJC == null) {
            synchronized (zzf.class) {
                if (zzJC == null) {
                    zzlb zzoQ = zzld.zzoQ();
                    long elapsedRealtime = zzoQ.elapsedRealtime();
                    zzf zzfVar = new zzf(new zzg(context.getApplicationContext()));
                    zzJC = zzfVar;
                    GoogleAnalytics.zzhj();
                    long elapsedRealtime2 = zzoQ.elapsedRealtime() - elapsedRealtime;
                    long longValue = zzy.zzLP.get().longValue();
                    if (elapsedRealtime2 > longValue) {
                        zzfVar.zzhQ().zzc("Slow initialization (ms)", Long.valueOf(elapsedRealtime2), Long.valueOf(longValue));
                    }
                }
            }
        }
        return zzJC;
    }

    private void zza(zzd zzdVar) {
        com.google.android.gms.common.internal.zzu.zzb(zzdVar, "Analytics service not created/initialized");
        com.google.android.gms.common.internal.zzu.zzb(zzdVar.isInitialized(), "Analytics service not initialized");
    }

    public Context getContext() {
        return this.mContext;
    }

    public void zzhO() {
        zzns.zzhO();
    }

    public zzlb zzhP() {
        return this.zzpw;
    }

    public zzaf zzhQ() {
        zza(this.zzJF);
        return this.zzJF;
    }

    public zzr zzhR() {
        return this.zzJE;
    }

    public zzns zzhS() {
        com.google.android.gms.common.internal.zzu.zzu(this.zzJG);
        return this.zzJG;
    }

    public zzv zzhT() {
        zza(this.zzJI);
        return this.zzJI;
    }

    public zzai zzhU() {
        zza(this.zzJK);
        return this.zzJK;
    }

    public zzk zzhX() {
        zza(this.zzJO);
        return this.zzJO;
    }

    public zzu zzhY() {
        return this.zzJP;
    }

    public zzb zzhl() {
        zza(this.zzJH);
        return this.zzJH;
    }

    public zzan zzhm() {
        zza(this.zzJJ);
        return this.zzJJ;
    }

    protected Thread.UncaughtExceptionHandler zzib() {
        return new Thread.UncaughtExceptionHandler() { // from class: com.google.android.gms.analytics.internal.zzf.1
            @Override // java.lang.Thread.UncaughtExceptionHandler
            public void uncaughtException(Thread thread, Throwable error) {
                zzaf zzid = zzf.this.zzid();
                if (zzid != null) {
                    zzid.zze("Job execution failed", error);
                }
            }
        };
    }

    public Context zzic() {
        return this.zzJD;
    }

    public zzaf zzid() {
        return this.zzJF;
    }

    public GoogleAnalytics zzie() {
        com.google.android.gms.common.internal.zzu.zzu(this.zzJL);
        com.google.android.gms.common.internal.zzu.zzb(this.zzJL.isInitialized(), "Analytics instance not initialized");
        return this.zzJL;
    }

    public zzai zzif() {
        if (this.zzJK == null || !this.zzJK.isInitialized()) {
            return null;
        }
        return this.zzJK;
    }

    public zza zzig() {
        zza(this.zzJN);
        return this.zzJN;
    }

    public zzn zzih() {
        zza(this.zzJM);
        return this.zzJM;
    }
}
