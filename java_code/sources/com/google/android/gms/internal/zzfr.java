package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.internal.zzfs;
import com.google.android.gms.internal.zzft;
import com.google.android.gms.internal.zzha;
@zzgd
/* loaded from: classes.dex */
public class zzfr extends zzfp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public zzfr(Context context, zzha.zza zzaVar, zzid zzidVar, zzft.zza zzaVar2) {
        super(context, zzaVar, zzidVar, zzaVar2);
    }

    @Override // com.google.android.gms.internal.zzfs
    protected void zzh(long j) throws zzfs.zza {
        int i;
        int i2;
        AdSizeParcel zzaN = this.zzoA.zzaN();
        if (zzaN.zzsn) {
            i = this.mContext.getResources().getDisplayMetrics().widthPixels;
            i2 = this.mContext.getResources().getDisplayMetrics().heightPixels;
        } else {
            i = zzaN.widthPixels;
            i2 = zzaN.heightPixels;
        }
        final zzfq zzfqVar = new zzfq(this, this.zzoA, i, i2);
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzfr.1
            @Override // java.lang.Runnable
            public void run() {
                synchronized (zzfr.this.zzqt) {
                    if (zzfr.this.zzBt.errorCode != -2) {
                        return;
                    }
                    zzfr.this.zzoA.zzgF().zza(zzfr.this);
                    zzfqVar.zza(zzfr.this.zzBt);
                }
            }
        });
        zzg(j);
        if (zzfqVar.zzfl()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Ad-Network indicated no fill with passback URL.");
            throw new zzfs.zza("AdNetwork sent passback url", 3);
        } else if (!zzfqVar.zzfm()) {
            throw new zzfs.zza("AdNetwork timed out", 2);
        }
    }
}
