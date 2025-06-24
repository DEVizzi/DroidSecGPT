package com.google.android.gms.internal;

import com.google.android.gms.ads.formats.NativeAppInstallAd;
import com.google.android.gms.internal.zzcu;
@zzgd
/* loaded from: classes.dex */
public class zzcz extends zzcu.zza {
    private final NativeAppInstallAd.OnAppInstallAdLoadedListener zzvQ;

    public zzcz(NativeAppInstallAd.OnAppInstallAdLoadedListener onAppInstallAdLoadedListener) {
        this.zzvQ = onAppInstallAdLoadedListener;
    }

    @Override // com.google.android.gms.internal.zzcu
    public void zza(zzco zzcoVar) {
        this.zzvQ.onAppInstallAdLoaded(zzb(zzcoVar));
    }

    zzcp zzb(zzco zzcoVar) {
        return new zzcp(zzcoVar);
    }
}
