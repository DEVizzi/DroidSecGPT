package com.google.android.gms.internal;

import android.content.Context;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import com.google.android.gms.internal.zzfs;
import com.google.android.gms.internal.zzft;
import com.google.android.gms.internal.zzha;
@zzgd
/* loaded from: classes.dex */
public class zzfw extends zzfs {
    private zzdw zzBA;
    protected zzec zzBB;
    private zzef zzoq;
    private zzdy zzxn;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzfw(Context context, zzha.zza zzaVar, zzid zzidVar, zzef zzefVar, zzft.zza zzaVar2) {
        super(context, zzaVar, zzidVar, zzaVar2);
        this.zzoq = zzefVar;
        this.zzxn = zzaVar.zzFm;
    }

    @Override // com.google.android.gms.internal.zzfs, com.google.android.gms.internal.zzhh
    public void onStop() {
        synchronized (this.zzBr) {
            super.onStop();
            if (this.zzBA != null) {
                this.zzBA.cancel();
            }
        }
    }

    @Override // com.google.android.gms.internal.zzfs
    protected void zzh(long j) throws zzfs.zza {
        synchronized (this.zzBr) {
            this.zzBA = new zzdw(this.mContext, this.zzBs.zzFr, this.zzoq, this.zzxn);
        }
        this.zzBB = this.zzBA.zza(j, 60000L);
        switch (this.zzBB.zzxY) {
            case 0:
                return;
            case 1:
                throw new zzfs.zza("No fill from any mediation ad networks.", 3);
            default:
                throw new zzfs.zza("Unexpected mediation result: " + this.zzBB.zzxY, 0);
        }
    }

    @Override // com.google.android.gms.internal.zzfs
    protected zzha zzz(int i) {
        AdRequestInfoParcel adRequestInfoParcel = this.zzBs.zzFr;
        return new zzha(adRequestInfoParcel.zzCm, this.zzoA, this.zzBt.zzxF, i, this.zzBt.zzxG, this.zzBt.zzCM, this.zzBt.orientation, this.zzBt.zzxJ, adRequestInfoParcel.zzCp, this.zzBt.zzCK, this.zzBB != null ? this.zzBB.zzxZ : null, this.zzBB != null ? this.zzBB.zzya : null, this.zzBB != null ? this.zzBB.zzyb : AdMobAdapter.class.getName(), this.zzxn, this.zzBB != null ? this.zzBB.zzyc : null, this.zzBt.zzCL, this.zzBs.zzpN, this.zzBt.zzCJ, this.zzBs.zzFo, this.zzBt.zzCO, this.zzBt.zzCP, this.zzBs.zzFl, null, adRequestInfoParcel.zzCC);
    }
}
