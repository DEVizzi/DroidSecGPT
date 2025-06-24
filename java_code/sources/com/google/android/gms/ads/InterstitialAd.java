package com.google.android.gms.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.client.zzz;
import com.google.android.gms.ads.purchase.InAppPurchaseListener;
import com.google.android.gms.ads.purchase.PlayStorePurchaseListener;
/* loaded from: classes.dex */
public final class InterstitialAd {
    private final zzz zznQ;

    public InterstitialAd(Context context) {
        this.zznQ = new zzz(context);
    }

    public AdListener getAdListener() {
        return this.zznQ.getAdListener();
    }

    public String getAdUnitId() {
        return this.zznQ.getAdUnitId();
    }

    public InAppPurchaseListener getInAppPurchaseListener() {
        return this.zznQ.getInAppPurchaseListener();
    }

    public String getMediationAdapterClassName() {
        return this.zznQ.getMediationAdapterClassName();
    }

    public boolean isLoaded() {
        return this.zznQ.isLoaded();
    }

    public void loadAd(AdRequest adRequest) {
        this.zznQ.zza(adRequest.zzaF());
    }

    public void setAdListener(AdListener adListener) {
        this.zznQ.setAdListener(adListener);
        if (adListener != null && (adListener instanceof com.google.android.gms.ads.internal.client.zza)) {
            this.zznQ.zza((com.google.android.gms.ads.internal.client.zza) adListener);
        } else if (adListener == null) {
            this.zznQ.zza((com.google.android.gms.ads.internal.client.zza) null);
        }
    }

    public void setAdUnitId(String adUnitId) {
        this.zznQ.setAdUnitId(adUnitId);
    }

    public void setInAppPurchaseListener(InAppPurchaseListener inAppPurchaseListener) {
        this.zznQ.setInAppPurchaseListener(inAppPurchaseListener);
    }

    public void setPlayStorePurchaseParams(PlayStorePurchaseListener playStorePurchaseListener, String publicKey) {
        this.zznQ.setPlayStorePurchaseParams(playStorePurchaseListener, publicKey);
    }

    public void show() {
        this.zznQ.show();
    }
}
