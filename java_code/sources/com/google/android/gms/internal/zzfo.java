package com.google.android.gms.internal;

import com.google.android.gms.ads.purchase.PlayStorePurchaseListener;
import com.google.android.gms.internal.zzfj;
@zzgd
/* loaded from: classes.dex */
public final class zzfo extends zzfj.zza {
    private final PlayStorePurchaseListener zzsX;

    public zzfo(PlayStorePurchaseListener playStorePurchaseListener) {
        this.zzsX = playStorePurchaseListener;
    }

    @Override // com.google.android.gms.internal.zzfj
    public boolean isValidPurchase(String productId) {
        return this.zzsX.isValidPurchase(productId);
    }

    @Override // com.google.android.gms.internal.zzfj
    public void zza(zzfi zzfiVar) {
        this.zzsX.onInAppPurchaseFinished(new zzfm(zzfiVar));
    }
}
