package com.google.android.gms.ads.internal.client;

import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.internal.client.zzn;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class zzc extends zzn.zza {
    private final AdListener zzrV;

    public zzc(AdListener adListener) {
        this.zzrV = adListener;
    }

    @Override // com.google.android.gms.ads.internal.client.zzn
    public void onAdClosed() {
        this.zzrV.onAdClosed();
    }

    @Override // com.google.android.gms.ads.internal.client.zzn
    public void onAdFailedToLoad(int errorCode) {
        this.zzrV.onAdFailedToLoad(errorCode);
    }

    @Override // com.google.android.gms.ads.internal.client.zzn
    public void onAdLeftApplication() {
        this.zzrV.onAdLeftApplication();
    }

    @Override // com.google.android.gms.ads.internal.client.zzn
    public void onAdLoaded() {
        this.zzrV.onAdLoaded();
    }

    @Override // com.google.android.gms.ads.internal.client.zzn
    public void onAdOpened() {
        this.zzrV.onAdOpened();
    }
}
