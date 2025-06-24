package com.google.android.gms.common.api;

import com.google.android.gms.common.api.zzi;
import com.google.android.gms.common.data.DataHolder;
/* loaded from: classes.dex */
public abstract class zzb<L> implements zzi.zzb<L> {
    private final DataHolder zzWu;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzb(DataHolder dataHolder) {
        this.zzWu = dataHolder;
    }

    protected abstract void zza(L l, DataHolder dataHolder);

    @Override // com.google.android.gms.common.api.zzi.zzb
    public void zzmw() {
        if (this.zzWu != null) {
            this.zzWu.close();
        }
    }

    @Override // com.google.android.gms.common.api.zzi.zzb
    public final void zzn(L l) {
        zza(l, this.zzWu);
    }
}
