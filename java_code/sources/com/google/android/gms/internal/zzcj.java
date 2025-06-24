package com.google.android.gms.internal;

import com.google.android.gms.ads.doubleclick.OnCustomRenderedAdLoadedListener;
import com.google.android.gms.internal.zzci;
@zzgd
/* loaded from: classes.dex */
public final class zzcj extends zzci.zza {
    private final OnCustomRenderedAdLoadedListener zzsY;

    public zzcj(OnCustomRenderedAdLoadedListener onCustomRenderedAdLoadedListener) {
        this.zzsY = onCustomRenderedAdLoadedListener;
    }

    @Override // com.google.android.gms.internal.zzci
    public void zza(zzch zzchVar) {
        this.zzsY.onCustomRenderedAdLoaded(new zzcg(zzchVar));
    }
}
