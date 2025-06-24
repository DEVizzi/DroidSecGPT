package com.google.android.gms.ads.internal.client;

import com.google.android.gms.internal.zzcy;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public class zzk {
    private static final Object zzoW = new Object();
    private static zzk zzss;
    private final com.google.android.gms.ads.internal.util.client.zza zzst = new com.google.android.gms.ads.internal.util.client.zza();
    private final zze zzsu = new zze();
    private final zzl zzsv = new zzl();
    private final zzac zzsw = new zzac();
    private final zzcy zzsx = new zzcy();
    private final com.google.android.gms.ads.internal.reward.client.zzf zzsy = new com.google.android.gms.ads.internal.reward.client.zzf();

    static {
        zza(new zzk());
    }

    protected zzk() {
    }

    protected static void zza(zzk zzkVar) {
        synchronized (zzoW) {
            zzss = zzkVar;
        }
    }

    public static com.google.android.gms.ads.internal.util.client.zza zzcA() {
        return zzcz().zzst;
    }

    public static zze zzcB() {
        return zzcz().zzsu;
    }

    public static zzl zzcC() {
        return zzcz().zzsv;
    }

    public static zzac zzcD() {
        return zzcz().zzsw;
    }

    public static zzcy zzcE() {
        return zzcz().zzsx;
    }

    public static com.google.android.gms.ads.internal.reward.client.zzf zzcF() {
        return zzcz().zzsy;
    }

    private static zzk zzcz() {
        zzk zzkVar;
        synchronized (zzoW) {
            zzkVar = zzss;
        }
        return zzkVar;
    }
}
