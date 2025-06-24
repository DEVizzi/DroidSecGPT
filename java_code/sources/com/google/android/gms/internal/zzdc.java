package com.google.android.gms.internal;

import com.google.android.gms.ads.formats.NativeCustomTemplateAd;
import com.google.android.gms.internal.zzcx;
@zzgd
/* loaded from: classes.dex */
public class zzdc extends zzcx.zza {
    private final NativeCustomTemplateAd.OnCustomTemplateAdLoadedListener zzvT;

    public zzdc(NativeCustomTemplateAd.OnCustomTemplateAdLoadedListener onCustomTemplateAdLoadedListener) {
        this.zzvT = onCustomTemplateAdLoadedListener;
    }

    @Override // com.google.android.gms.internal.zzcx
    public void zza(zzcs zzcsVar) {
        this.zzvT.onCustomTemplateAdLoaded(new zzct(zzcsVar));
    }
}
