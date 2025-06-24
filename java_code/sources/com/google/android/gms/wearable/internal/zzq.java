package com.google.android.gms.wearable.internal;

import com.google.android.gms.wearable.internal.zzaq;
/* loaded from: classes.dex */
public final class zzq extends zzaq.zza {
    private zzj zzaTY;
    private zzr zzaUc;
    private final Object zzqt = new Object();

    public void zza(zzr zzrVar) {
        zzj zzjVar;
        synchronized (this.zzqt) {
            this.zzaUc = (zzr) com.google.android.gms.common.internal.zzu.zzu(zzrVar);
            zzjVar = this.zzaTY;
        }
        if (zzjVar != null) {
            zzrVar.zzb(zzjVar);
        }
    }

    @Override // com.google.android.gms.wearable.internal.zzaq
    public void zzw(int i, int i2) {
        zzr zzrVar;
        zzj zzjVar;
        synchronized (this.zzqt) {
            zzrVar = this.zzaUc;
            zzjVar = new zzj(i, i2);
            this.zzaTY = zzjVar;
        }
        if (zzrVar != null) {
            zzrVar.zzb(zzjVar);
        }
    }
}
