package com.google.android.gms.internal;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.res.Resources;
import android.os.Bundle;
import android.os.Parcelable;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.internal.zzhj;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.concurrent.Future;
@zzgd
/* loaded from: classes.dex */
public class zzhc implements zzhj.zzb {
    private Context mContext;
    private final String zzFE;
    private final zzhd zzFF;
    private String zzFP;
    private VersionInfoParcel zzoM;
    private zzay zzop;
    private final Object zzqt = new Object();
    private BigInteger zzFG = BigInteger.ONE;
    private final HashSet<zzhb> zzFH = new HashSet<>();
    private final HashMap<String, zzhf> zzFI = new HashMap<>();
    private boolean zzFJ = false;
    private boolean zzEd = true;
    private int zzFK = 0;
    private boolean zzpb = false;
    private zzcb zzFL = null;
    private boolean zzEe = true;
    private zzbj zzrw = null;
    private zzbk zzFM = null;
    private zzbi zzrx = null;
    private final LinkedList<Thread> zzFN = new LinkedList<>();
    private final zzgc zzry = null;
    private Boolean zzFO = null;

    public zzhc(zzhl zzhlVar) {
        this.zzFE = zzhlVar.zzgn();
        this.zzFF = new zzhd(this.zzFE);
    }

    public String getSessionId() {
        return this.zzFE;
    }

    public void zzA(boolean z) {
        synchronized (this.zzqt) {
            this.zzEe = z;
        }
    }

    public zzbk zzD(Context context) {
        if (zzbz.zzuc.get().booleanValue() && zzlk.zzoU() && !zzfV()) {
            synchronized (this.zzqt) {
                if (this.zzrw == null) {
                    if (!(context instanceof Activity)) {
                        return null;
                    }
                    this.zzrw = new zzbj((Application) context.getApplicationContext(), (Activity) context);
                }
                if (this.zzrx == null) {
                    this.zzrx = new zzbi();
                }
                if (this.zzFM == null) {
                    this.zzFM = new zzbk(this.zzrw, this.zzrx, new zzgc(this.mContext, this.zzoM, null, null));
                }
                this.zzFM.zzcp();
                return this.zzFM;
            }
        }
        return null;
    }

    public Bundle zza(Context context, zzhe zzheVar, String str) {
        Bundle bundle;
        synchronized (this.zzqt) {
            bundle = new Bundle();
            bundle.putBundle("app", this.zzFF.zzd(context, str));
            Bundle bundle2 = new Bundle();
            for (String str2 : this.zzFI.keySet()) {
                bundle2.putBundle(str2, this.zzFI.get(str2).toBundle());
            }
            bundle.putBundle("slots", bundle2);
            ArrayList<? extends Parcelable> arrayList = new ArrayList<>();
            Iterator<zzhb> it = this.zzFH.iterator();
            while (it.hasNext()) {
                arrayList.add(it.next().toBundle());
            }
            bundle.putParcelableArrayList("ads", arrayList);
            zzheVar.zza(this.zzFH);
            this.zzFH.clear();
        }
        return bundle;
    }

    public Future zza(Context context, boolean z) {
        Future future;
        synchronized (this.zzqt) {
            if (z != this.zzEd) {
                this.zzEd = z;
                future = zzhj.zza(context, z);
            } else {
                future = null;
            }
        }
        return future;
    }

    public void zza(zzhb zzhbVar) {
        synchronized (this.zzqt) {
            this.zzFH.add(zzhbVar);
        }
    }

    public void zza(String str, zzhf zzhfVar) {
        synchronized (this.zzqt) {
            this.zzFI.put(str, zzhfVar);
        }
    }

    public void zza(Thread thread) {
        zzgc.zza(this.mContext, thread, this.zzoM);
    }

    public void zzb(Context context, VersionInfoParcel versionInfoParcel) {
        synchronized (this.zzqt) {
            if (!this.zzpb) {
                this.mContext = context.getApplicationContext();
                this.zzoM = versionInfoParcel;
                zzhj.zza(context, this);
                zzhj.zzb(context, this);
                zza(Thread.currentThread());
                this.zzFP = com.google.android.gms.ads.internal.zzo.zzbv().zzf(context, versionInfoParcel.zzGG);
                this.zzop = new zzay(context.getApplicationContext(), this.zzoM, new zzdt(context.getApplicationContext(), this.zzoM, zzbz.zztD.get()));
                zzgf();
                this.zzpb = true;
            }
        }
    }

    public void zzb(Boolean bool) {
        synchronized (this.zzqt) {
            this.zzFO = bool;
        }
    }

    public void zzb(HashSet<zzhb> hashSet) {
        synchronized (this.zzqt) {
            this.zzFH.addAll(hashSet);
        }
    }

    public String zzc(int i, String str) {
        Resources resources = this.zzoM.zzGJ ? this.mContext.getResources() : GooglePlayServicesUtil.getRemoteResource(this.mContext);
        return resources == null ? str : resources.getString(i);
    }

    @Override // com.google.android.gms.internal.zzhj.zzb
    public void zzc(Bundle bundle) {
        synchronized (this.zzqt) {
            this.zzEd = bundle.containsKey("use_https") ? bundle.getBoolean("use_https") : this.zzEd;
            this.zzFK = bundle.containsKey("webview_cache_version") ? bundle.getInt("webview_cache_version") : this.zzFK;
        }
    }

    public void zzc(Throwable th, boolean z) {
        new zzgc(this.mContext, this.zzoM, null, null).zza(th, z);
    }

    public boolean zzfV() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzEe;
        }
        return z;
    }

    public String zzfW() {
        String bigInteger;
        synchronized (this.zzqt) {
            bigInteger = this.zzFG.toString();
            this.zzFG = this.zzFG.add(BigInteger.ONE);
        }
        return bigInteger;
    }

    public zzhd zzfX() {
        zzhd zzhdVar;
        synchronized (this.zzqt) {
            zzhdVar = this.zzFF;
        }
        return zzhdVar;
    }

    public zzcb zzfY() {
        zzcb zzcbVar;
        synchronized (this.zzqt) {
            zzcbVar = this.zzFL;
        }
        return zzcbVar;
    }

    public boolean zzfZ() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzFJ;
            this.zzFJ = true;
        }
        return z;
    }

    public boolean zzga() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzEd;
        }
        return z;
    }

    public String zzgb() {
        String str;
        synchronized (this.zzqt) {
            str = this.zzFP;
        }
        return str;
    }

    public Boolean zzgc() {
        Boolean bool;
        synchronized (this.zzqt) {
            bool = this.zzFO;
        }
        return bool;
    }

    public zzay zzgd() {
        return this.zzop;
    }

    public boolean zzge() {
        boolean z;
        synchronized (this.zzqt) {
            if (this.zzFK < zzbz.zzup.get().intValue()) {
                this.zzFK = zzbz.zzup.get().intValue();
                zzhj.zza(this.mContext, this.zzFK);
                z = true;
            } else {
                z = false;
            }
        }
        return z;
    }

    void zzgf() {
        zzca zzcaVar = new zzca();
        zzcaVar.zzb(this.mContext, this.zzoM.zzGG);
        try {
            this.zzFL = com.google.android.gms.ads.internal.zzo.zzbA().zza(zzcaVar);
        } catch (IllegalArgumentException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Cannot initialize CSI reporter.", e);
        }
    }
}
