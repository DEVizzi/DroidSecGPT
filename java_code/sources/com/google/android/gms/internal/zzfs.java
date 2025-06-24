package com.google.android.gms.internal;

import android.content.Context;
import android.os.SystemClock;
import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import com.google.android.gms.ads.internal.request.AdResponseParcel;
import com.google.android.gms.internal.zzft;
import com.google.android.gms.internal.zzha;
@zzgd
/* loaded from: classes.dex */
public abstract class zzfs extends zzhh {
    protected final Context mContext;
    protected final zzft.zza zzBq;
    protected final zzha.zza zzBs;
    protected AdResponseParcel zzBt;
    protected final zzid zzoA;
    protected final Object zzqt = new Object();
    protected final Object zzBr = new Object();

    /* loaded from: classes.dex */
    protected static final class zza extends Exception {
        private final int zzBv;

        public zza(String str, int i) {
            super(str);
            this.zzBv = i;
        }

        public int getErrorCode() {
            return this.zzBv;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzfs(Context context, zzha.zza zzaVar, zzid zzidVar, zzft.zza zzaVar2) {
        this.mContext = context;
        this.zzBs = zzaVar;
        this.zzBt = zzaVar.zzFs;
        this.zzoA = zzidVar;
        this.zzBq = zzaVar2;
    }

    @Override // com.google.android.gms.internal.zzhh
    public void onStop() {
    }

    @Override // com.google.android.gms.internal.zzhh
    public void zzdP() {
        synchronized (this.zzqt) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("AdRendererBackgroundTask started.");
            int i = this.zzBs.errorCode;
            try {
                zzh(SystemClock.elapsedRealtime());
            } catch (zza e) {
                int errorCode = e.getErrorCode();
                if (errorCode == 3 || errorCode == -1) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaA(e.getMessage());
                } else {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC(e.getMessage());
                }
                if (this.zzBt == null) {
                    this.zzBt = new AdResponseParcel(errorCode);
                } else {
                    this.zzBt = new AdResponseParcel(errorCode, this.zzBt.zzxJ);
                }
                zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzfs.1
                    @Override // java.lang.Runnable
                    public void run() {
                        zzfs.this.onStop();
                    }
                });
                i = errorCode;
            }
            final zzha zzz = zzz(i);
            zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzfs.2
                @Override // java.lang.Runnable
                public void run() {
                    synchronized (zzfs.this.zzqt) {
                        zzfs.this.zzk(zzz);
                    }
                }
            });
        }
    }

    protected abstract void zzh(long j) throws zza;

    /* JADX INFO: Access modifiers changed from: protected */
    public void zzk(zzha zzhaVar) {
        this.zzBq.zzb(zzhaVar);
    }

    protected zzha zzz(int i) {
        AdRequestInfoParcel adRequestInfoParcel = this.zzBs.zzFr;
        return new zzha(adRequestInfoParcel.zzCm, this.zzoA, this.zzBt.zzxF, i, this.zzBt.zzxG, this.zzBt.zzCM, this.zzBt.orientation, this.zzBt.zzxJ, adRequestInfoParcel.zzCp, this.zzBt.zzCK, null, null, null, null, null, this.zzBt.zzCL, this.zzBs.zzpN, this.zzBt.zzCJ, this.zzBs.zzFo, this.zzBt.zzCO, this.zzBt.zzCP, this.zzBs.zzFl, null, adRequestInfoParcel.zzCC);
    }
}
