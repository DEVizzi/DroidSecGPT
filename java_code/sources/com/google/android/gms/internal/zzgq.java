package com.google.android.gms.internal;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.internal.zzha;
@zzgd
/* loaded from: classes.dex */
public class zzgq extends zzhh implements zzgr, zzgu {
    private final Context mContext;
    private final zzha.zza zzBs;
    private final String zzEO;
    private final zzgp zzEV;
    private final zzgu zzEW;
    private final String zzEX;
    private final String zzxQ;
    private int zzEY = 0;
    private int zzBv = 3;
    private final Object zzqt = new Object();

    public zzgq(Context context, String str, String str2, String str3, zzha.zza zzaVar, zzgp zzgpVar, zzgu zzguVar) {
        this.mContext = context;
        this.zzxQ = str;
        this.zzEO = str2;
        this.zzEX = str3;
        this.zzBs = zzaVar;
        this.zzEV = zzgpVar;
        this.zzEW = zzguVar;
    }

    private void zzk(long j) {
        while (true) {
            synchronized (this.zzqt) {
                if (this.zzEY != 0) {
                    return;
                }
                if (!zze(j)) {
                    return;
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.zzhh
    public void onStop() {
    }

    @Override // com.google.android.gms.internal.zzgr
    public void zzI(int i) {
        zzb(this.zzxQ, 0);
    }

    @Override // com.google.android.gms.internal.zzgu
    public void zzap(String str) {
        synchronized (this.zzqt) {
            this.zzEY = 1;
            this.zzqt.notify();
        }
    }

    @Override // com.google.android.gms.internal.zzgu
    public void zzb(String str, int i) {
        synchronized (this.zzqt) {
            this.zzEY = 2;
            this.zzBv = i;
            this.zzqt.notify();
        }
    }

    @Override // com.google.android.gms.internal.zzhh
    public void zzdP() {
        if (this.zzEV == null || this.zzEV.zzfN() == null || this.zzEV.zzfM() == null) {
            return;
        }
        final zzgt zzfN = this.zzEV.zzfN();
        zzfN.zza((zzgu) this);
        zzfN.zza((zzgr) this);
        final AdRequestParcel adRequestParcel = this.zzBs.zzFr.zzCm;
        final zzeg zzfM = this.zzEV.zzfM();
        try {
            if (zzfM.isInitialized()) {
                com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzgq.1
                    @Override // java.lang.Runnable
                    public void run() {
                        try {
                            zzfM.zza(adRequestParcel, zzgq.this.zzEX);
                        } catch (RemoteException e) {
                            com.google.android.gms.ads.internal.util.client.zzb.zzd("Fail to load ad from adapter.", e);
                            zzgq.this.zzb(zzgq.this.zzxQ, 0);
                        }
                    }
                });
            } else {
                com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzgq.2
                    @Override // java.lang.Runnable
                    public void run() {
                        try {
                            zzfM.zza(com.google.android.gms.dynamic.zze.zzw(zzgq.this.mContext), adRequestParcel, zzgq.this.zzEO, zzfN, zzgq.this.zzEX);
                        } catch (RemoteException e) {
                            com.google.android.gms.ads.internal.util.client.zzb.zzd("Fail to initialize adapter " + zzgq.this.zzxQ, e);
                            zzgq.this.zzb(zzgq.this.zzxQ, 0);
                        }
                    }
                });
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Fail to check if adapter is initialized.", e);
            zzb(this.zzxQ, 0);
        }
        zzk(com.google.android.gms.ads.internal.zzo.zzbz().elapsedRealtime());
        zzfN.zza((zzgu) null);
        zzfN.zza((zzgr) null);
        if (this.zzEY == 1) {
            this.zzEW.zzap(this.zzxQ);
        } else {
            this.zzEW.zzb(this.zzxQ, this.zzBv);
        }
    }

    protected boolean zze(long j) {
        long elapsedRealtime = 20000 - (com.google.android.gms.ads.internal.zzo.zzbz().elapsedRealtime() - j);
        if (elapsedRealtime <= 0) {
            return false;
        }
        try {
            this.zzqt.wait(elapsedRealtime);
            return true;
        } catch (InterruptedException e) {
            return false;
        }
    }

    @Override // com.google.android.gms.internal.zzgr
    public void zzfO() {
        this.zzEV.zzfN();
        AdRequestParcel adRequestParcel = this.zzBs.zzFr.zzCm;
        try {
            this.zzEV.zzfM().zza(adRequestParcel, this.zzEX);
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Fail to load ad from adapter.", e);
            zzb(this.zzxQ, 0);
        }
    }
}
