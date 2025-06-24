package com.google.android.gms.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import android.os.SystemClock;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzec;
@zzgd
/* loaded from: classes.dex */
public final class zzeb implements zzec.zza {
    private final Context mContext;
    private final VersionInfoParcel zzoM;
    private final zzef zzoq;
    private final AdRequestParcel zzph;
    private final String zzxQ;
    private final long zzxR;
    private final zzdx zzxS;
    private final AdSizeParcel zzxT;
    private zzeg zzxU;
    private final Object zzqt = new Object();
    private int zzxV = -2;

    public zzeb(Context context, String str, zzef zzefVar, zzdy zzdyVar, zzdx zzdxVar, AdRequestParcel adRequestParcel, AdSizeParcel adSizeParcel, VersionInfoParcel versionInfoParcel) {
        this.mContext = context;
        this.zzoq = zzefVar;
        this.zzxS = zzdxVar;
        if ("com.google.ads.mediation.customevent.CustomEventAdapter".equals(str)) {
            this.zzxQ = zzdZ();
        } else {
            this.zzxQ = str;
        }
        this.zzxR = zzdyVar.zzxE != -1 ? zzdyVar.zzxE : 10000L;
        this.zzph = adRequestParcel;
        this.zzxT = adSizeParcel;
        this.zzoM = versionInfoParcel;
    }

    private void zza(long j, long j2, long j3, long j4) {
        while (this.zzxV == -2) {
            zzb(j, j2, j3, j4);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zza(zzea zzeaVar) {
        if (zzbz.zzuu.get().booleanValue() && "com.google.ads.mediation.AdUrlAdapter".equals(this.zzxQ)) {
            Bundle bundle = this.zzph.zzsh.getBundle(this.zzxQ);
            if (bundle == null) {
                bundle = new Bundle();
            }
            bundle.putString("sdk_less_network_id", this.zzxS.zzxt);
            this.zzph.zzsh.putBundle(this.zzxQ, bundle);
        }
        try {
            if (this.zzoM.zzGI < 4100000) {
                if (this.zzxT.zzsn) {
                    this.zzxU.zza(com.google.android.gms.dynamic.zze.zzw(this.mContext), this.zzph, this.zzxS.zzxz, zzeaVar);
                } else {
                    this.zzxU.zza(com.google.android.gms.dynamic.zze.zzw(this.mContext), this.zzxT, this.zzph, this.zzxS.zzxz, zzeaVar);
                }
            } else if (this.zzxT.zzsn) {
                this.zzxU.zza(com.google.android.gms.dynamic.zze.zzw(this.mContext), this.zzph, this.zzxS.zzxz, this.zzxS.zzxs, zzeaVar);
            } else {
                this.zzxU.zza(com.google.android.gms.dynamic.zze.zzw(this.mContext), this.zzxT, this.zzph, this.zzxS.zzxz, this.zzxS.zzxs, zzeaVar);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not request ad from mediation adapter.", e);
            zzs(5);
        }
    }

    private void zzb(long j, long j2, long j3, long j4) {
        long elapsedRealtime = SystemClock.elapsedRealtime();
        long j5 = j2 - (elapsedRealtime - j);
        long j6 = j4 - (elapsedRealtime - j3);
        if (j5 <= 0 || j6 <= 0) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("Timed out waiting for adapter.");
            this.zzxV = 3;
            return;
        }
        try {
            this.zzqt.wait(Math.min(j5, j6));
        } catch (InterruptedException e) {
            this.zzxV = -1;
        }
    }

    private String zzdZ() {
        try {
            if (!TextUtils.isEmpty(this.zzxS.zzxw)) {
                return this.zzoq.zzZ(this.zzxS.zzxw) ? "com.google.android.gms.ads.mediation.customevent.CustomEventAdapter" : "com.google.ads.mediation.customevent.CustomEventAdapter";
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to determine the custom event's version, assuming the old one.");
        }
        return "com.google.ads.mediation.customevent.CustomEventAdapter";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public zzeg zzea() {
        com.google.android.gms.ads.internal.util.client.zzb.zzaA("Instantiating mediation adapter: " + this.zzxQ);
        try {
            return this.zzoq.zzY(this.zzxQ);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zza("Could not instantiate mediation adapter: " + this.zzxQ, e);
            return null;
        }
    }

    public void cancel() {
        synchronized (this.zzqt) {
            try {
                if (this.zzxU != null) {
                    this.zzxU.destroy();
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not destroy mediation adapter.", e);
            }
            this.zzxV = -1;
            this.zzqt.notify();
        }
    }

    public zzec zzb(long j, long j2) {
        zzec zzecVar;
        synchronized (this.zzqt) {
            long elapsedRealtime = SystemClock.elapsedRealtime();
            final zzea zzeaVar = new zzea();
            zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzeb.1
                @Override // java.lang.Runnable
                public void run() {
                    synchronized (zzeb.this.zzqt) {
                        if (zzeb.this.zzxV != -2) {
                            return;
                        }
                        zzeb.this.zzxU = zzeb.this.zzea();
                        if (zzeb.this.zzxU == null) {
                            zzeb.this.zzs(4);
                            return;
                        }
                        zzeaVar.zza(zzeb.this);
                        zzeb.this.zza(zzeaVar);
                    }
                }
            });
            zza(elapsedRealtime, this.zzxR, j, j2);
            zzecVar = new zzec(this.zzxS, this.zzxU, this.zzxQ, zzeaVar, this.zzxV);
        }
        return zzecVar;
    }

    @Override // com.google.android.gms.internal.zzec.zza
    public void zzs(int i) {
        synchronized (this.zzqt) {
            this.zzxV = i;
            this.zzqt.notify();
        }
    }
}
