package com.google.android.gms.ads.purchase;

import android.content.Intent;
/* loaded from: classes.dex */
public interface InAppPurchaseResult {
    void finishPurchase();

    String getProductId();

    Intent getPurchaseData();

    int getResultCode();

    boolean isVerified();
}
