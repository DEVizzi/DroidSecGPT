package com.google.android.gms.ads.internal;

import android.os.Build;
import com.google.android.gms.internal.zzbw;
import com.google.android.gms.internal.zzbx;
import com.google.android.gms.internal.zzby;
import com.google.android.gms.internal.zzcc;
import com.google.android.gms.internal.zzdq;
import com.google.android.gms.internal.zzed;
import com.google.android.gms.internal.zzft;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzgl;
import com.google.android.gms.internal.zzhc;
import com.google.android.gms.internal.zzhl;
import com.google.android.gms.internal.zzhm;
import com.google.android.gms.internal.zzif;
import com.google.android.gms.internal.zzlb;
import com.google.android.gms.internal.zzld;
@zzgd
/* loaded from: classes.dex */
public class zzo {
    private static final Object zzoW = new Object();
    private static zzo zzpn;
    private final com.google.android.gms.ads.internal.request.zza zzpo = new com.google.android.gms.ads.internal.request.zza();
    private final com.google.android.gms.ads.internal.overlay.zza zzpp = new com.google.android.gms.ads.internal.overlay.zza();
    private final com.google.android.gms.ads.internal.overlay.zzd zzpq = new com.google.android.gms.ads.internal.overlay.zzd();
    private final zzft zzpr = new zzft();
    private final zzhl zzps = new zzhl();
    private final zzif zzpt = new zzif();
    private final zzhm zzpu = zzhm.zzK(Build.VERSION.SDK_INT);
    private final zzhc zzpv = new zzhc(this.zzps);
    private final zzlb zzpw = new zzld();
    private final zzcc zzpx = new zzcc();
    private final zzgl zzpy = new zzgl();
    private final zzbx zzpz = new zzbx();
    private final zzbw zzpA = new zzbw();
    private final zzby zzpB = new zzby();
    private final com.google.android.gms.ads.internal.purchase.zzi zzpC = new com.google.android.gms.ads.internal.purchase.zzi();
    private final zzed zzpD = new zzed();
    private final zzdq zzpE = new zzdq();

    static {
        zza(new zzo());
    }

    protected zzo() {
    }

    protected static void zza(zzo zzoVar) {
        synchronized (zzoW) {
            zzpn = zzoVar;
        }
    }

    public static zzcc zzbA() {
        return zzbq().zzpx;
    }

    public static zzgl zzbB() {
        return zzbq().zzpy;
    }

    public static zzbx zzbC() {
        return zzbq().zzpz;
    }

    public static zzbw zzbD() {
        return zzbq().zzpA;
    }

    public static zzby zzbE() {
        return zzbq().zzpB;
    }

    public static com.google.android.gms.ads.internal.purchase.zzi zzbF() {
        return zzbq().zzpC;
    }

    public static zzed zzbG() {
        return zzbq().zzpD;
    }

    public static zzdq zzbH() {
        return zzbq().zzpE;
    }

    private static zzo zzbq() {
        zzo zzoVar;
        synchronized (zzoW) {
            zzoVar = zzpn;
        }
        return zzoVar;
    }

    public static com.google.android.gms.ads.internal.request.zza zzbr() {
        return zzbq().zzpo;
    }

    public static com.google.android.gms.ads.internal.overlay.zza zzbs() {
        return zzbq().zzpp;
    }

    public static com.google.android.gms.ads.internal.overlay.zzd zzbt() {
        return zzbq().zzpq;
    }

    public static zzft zzbu() {
        return zzbq().zzpr;
    }

    public static zzhl zzbv() {
        return zzbq().zzps;
    }

    public static zzif zzbw() {
        return zzbq().zzpt;
    }

    public static zzhm zzbx() {
        return zzbq().zzpu;
    }

    public static zzhc zzby() {
        return zzbq().zzpv;
    }

    public static zzlb zzbz() {
        return zzbq().zzpw;
    }
}
