package com.google.android.gms.analytics.internal;

import android.content.Context;
import android.content.Intent;
import com.google.android.gms.analytics.AnalyticsReceiver;
import com.google.android.gms.analytics.AnalyticsService;
import com.google.android.gms.internal.zzns;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
/* loaded from: classes.dex */
public class zzb extends zzd {
    private final zzl zzJq;

    public zzb(zzf zzfVar, zzg zzgVar) {
        super(zzfVar);
        com.google.android.gms.common.internal.zzu.zzu(zzgVar);
        this.zzJq = zzgVar.zzj(zzfVar);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void onServiceConnected() {
        zzhO();
        this.zzJq.onServiceConnected();
    }

    public void setLocalDispatchPeriod(final int dispatchPeriodInSeconds) {
        zzia();
        zzb("setLocalDispatchPeriod (sec)", Integer.valueOf(dispatchPeriodInSeconds));
        zzhS().zze(new Runnable() { // from class: com.google.android.gms.analytics.internal.zzb.1
            @Override // java.lang.Runnable
            public void run() {
                zzb.this.zzJq.zzs(dispatchPeriodInSeconds * 1000);
            }
        });
    }

    public void start() {
        this.zzJq.start();
    }

    public void zzG(final boolean z) {
        zza("Network connectivity status changed", Boolean.valueOf(z));
        zzhS().zze(new Runnable() { // from class: com.google.android.gms.analytics.internal.zzb.2
            @Override // java.lang.Runnable
            public void run() {
                zzb.this.zzJq.zzG(z);
            }
        });
    }

    public long zza(zzh zzhVar) {
        zzia();
        com.google.android.gms.common.internal.zzu.zzu(zzhVar);
        zzhO();
        long zza = this.zzJq.zza(zzhVar, true);
        if (zza == 0) {
            this.zzJq.zzc(zzhVar);
        }
        return zza;
    }

    public void zza(final zzab zzabVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzabVar);
        zzia();
        zzb("Hit delivery requested", zzabVar);
        zzhS().zze(new Runnable() { // from class: com.google.android.gms.analytics.internal.zzb.4
            @Override // java.lang.Runnable
            public void run() {
                zzb.this.zzJq.zza(zzabVar);
            }
        });
    }

    public void zza(final zzw zzwVar) {
        zzia();
        zzhS().zze(new Runnable() { // from class: com.google.android.gms.analytics.internal.zzb.6
            @Override // java.lang.Runnable
            public void run() {
                zzb.this.zzJq.zzb(zzwVar);
            }
        });
    }

    public void zza(final String str, final Runnable runnable) {
        com.google.android.gms.common.internal.zzu.zzh(str, "campaign param can't be empty");
        zzhS().zze(new Runnable() { // from class: com.google.android.gms.analytics.internal.zzb.3
            @Override // java.lang.Runnable
            public void run() {
                zzb.this.zzJq.zzbb(str);
                if (runnable != null) {
                    runnable.run();
                }
            }
        });
    }

    public void zzhG() {
        zzia();
        zzhN();
        zzhS().zze(new Runnable() { // from class: com.google.android.gms.analytics.internal.zzb.5
            @Override // java.lang.Runnable
            public void run() {
                zzb.this.zzJq.zzhG();
            }
        });
    }

    public void zzhH() {
        zzia();
        Context context = getContext();
        if (!AnalyticsReceiver.zzT(context) || !AnalyticsService.zzU(context)) {
            zza((zzw) null);
            return;
        }
        Intent intent = new Intent(context, AnalyticsService.class);
        intent.setAction("com.google.android.gms.analytics.ANALYTICS_DISPATCH");
        context.startService(intent);
    }

    public boolean zzhI() {
        zzia();
        try {
            zzhS().zzb(new Callable<Void>() { // from class: com.google.android.gms.analytics.internal.zzb.7
                @Override // java.util.concurrent.Callable
                /* renamed from: zzgk */
                public Void call() throws Exception {
                    zzb.this.zzJq.zziF();
                    return null;
                }
            }).get();
            return true;
        } catch (InterruptedException e) {
            zzd("syncDispatchLocalHits interrupted", e);
            return false;
        } catch (ExecutionException e2) {
            zze("syncDispatchLocalHits failed", e2);
            return false;
        }
    }

    public void zzhJ() {
        zzia();
        zzns.zzhO();
        this.zzJq.zzhJ();
    }

    public void zzhK() {
        zzaT("Radio powered up");
        zzhH();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzhL() {
        zzhO();
        this.zzJq.zzhL();
    }

    @Override // com.google.android.gms.analytics.internal.zzd
    protected void zzhn() {
        this.zzJq.zza();
    }
}
