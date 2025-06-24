package com.google.android.gms.ads.doubleclick;

import android.content.Context;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.internal.client.zzz;
/* loaded from: classes.dex */
public final class PublisherInterstitialAd {
    private final zzz zznQ;

    public PublisherInterstitialAd(Context context) {
        this.zznQ = new zzz(context, this);
    }

    public AdListener getAdListener() {
        return this.zznQ.getAdListener();
    }

    public String getAdUnitId() {
        return this.zznQ.getAdUnitId();
    }

    public AppEventListener getAppEventListener() {
        return this.zznQ.getAppEventListener();
    }

    public String getMediationAdapterClassName() {
        return this.zznQ.getMediationAdapterClassName();
    }

    public OnCustomRenderedAdLoadedListener getOnCustomRenderedAdLoadedListener() {
        return this.zznQ.getOnCustomRenderedAdLoadedListener();
    }

    public boolean isLoaded() {
        return this.zznQ.isLoaded();
    }

    public void loadAd(PublisherAdRequest publisherAdRequest) {
        this.zznQ.zza(publisherAdRequest.zzaF());
    }

    public void setAdListener(AdListener adListener) {
        this.zznQ.setAdListener(adListener);
    }

    public void setAdUnitId(String adUnitId) {
        this.zznQ.setAdUnitId(adUnitId);
    }

    public void setAppEventListener(AppEventListener appEventListener) {
        this.zznQ.setAppEventListener(appEventListener);
    }

    public void setOnCustomRenderedAdLoadedListener(OnCustomRenderedAdLoadedListener onCustomRenderedAdLoadedListener) {
        this.zznQ.setOnCustomRenderedAdLoadedListener(onCustomRenderedAdLoadedListener);
    }

    public void show() {
        this.zznQ.show();
    }
}
