package com.google.android.gms.internal;

import com.google.android.gms.ads.purchase.InAppPurchaseListener;
import com.google.android.gms.internal.zzff;
@zzgd
/* loaded from: classes.dex */
public final class zzfk extends zzff.zza {
    private final InAppPurchaseListener zzsW;

    public zzfk(InAppPurchaseListener inAppPurchaseListener) {
        this.zzsW = inAppPurchaseListener;
    }

    @Override // com.google.android.gms.internal.zzff
    public void zza(zzfe zzfeVar) {
        this.zzsW.onInAppPurchaseRequested(new zzfn(zzfeVar));
    }
}
