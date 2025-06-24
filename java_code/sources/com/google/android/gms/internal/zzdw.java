package com.google.android.gms.internal;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
@zzgd
/* loaded from: classes.dex */
public final class zzdw {
    private final Context mContext;
    private final zzef zzoq;
    private final AdRequestInfoParcel zzxm;
    private final zzdy zzxn;
    private zzeb zzxp;
    private final Object zzqt = new Object();
    private boolean zzxo = false;

    public zzdw(Context context, AdRequestInfoParcel adRequestInfoParcel, zzef zzefVar, zzdy zzdyVar) {
        this.mContext = context;
        this.zzxm = adRequestInfoParcel;
        this.zzoq = zzefVar;
        this.zzxn = zzdyVar;
    }

    public void cancel() {
        synchronized (this.zzqt) {
            this.zzxo = true;
            if (this.zzxp != null) {
                this.zzxp.cancel();
            }
        }
    }

    public zzec zza(long j, long j2) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Starting mediation.");
        for (zzdx zzdxVar : this.zzxn.zzxD) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaA("Trying mediation network: " + zzdxVar.zzxt);
            for (String str : zzdxVar.zzxu) {
                synchronized (this.zzqt) {
                    if (this.zzxo) {
                        return new zzec(-1);
                    }
                    this.zzxp = new zzeb(this.mContext, str, this.zzoq, this.zzxn, zzdxVar, this.zzxm.zzCm, this.zzxm.zzpN, this.zzxm.zzpJ);
                    final zzec zzb = this.zzxp.zzb(j, j2);
                    if (zzb.zzxY == 0) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter succeeded.");
                        return zzb;
                    } else if (zzb.zzya != null) {
                        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzdw.1
                            @Override // java.lang.Runnable
                            public void run() {
                                try {
                                    zzb.zzya.destroy();
                                } catch (RemoteException e) {
                                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not destroy mediation adapter.", e);
                                }
                            }
                        });
                    }
                }
            }
        }
        return new zzec(1);
    }
}
