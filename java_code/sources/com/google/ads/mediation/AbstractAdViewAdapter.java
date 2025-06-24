package com.google.ads.mediation;

import android.content.Context;
import android.location.Location;
import android.os.Bundle;
import android.view.View;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.AdListener;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.AdSize;
import com.google.android.gms.ads.AdView;
import com.google.android.gms.ads.InterstitialAd;
import com.google.android.gms.ads.internal.client.zzk;
import com.google.android.gms.internal.zzgd;
import java.util.Date;
import java.util.Set;
@zzgd
/* loaded from: classes.dex */
public abstract class AbstractAdViewAdapter implements com.google.android.gms.ads.mediation.MediationBannerAdapter, com.google.android.gms.ads.mediation.MediationInterstitialAdapter {
    public static final String AD_UNIT_ID_PARAMETER = "pubid";
    private AdView zzaL;
    private InterstitialAd zzaM;

    /* loaded from: classes.dex */
    static final class zza extends AdListener implements com.google.android.gms.ads.internal.client.zza {
        final AbstractAdViewAdapter zzaN;
        final com.google.android.gms.ads.mediation.MediationBannerListener zzaO;

        public zza(AbstractAdViewAdapter abstractAdViewAdapter, com.google.android.gms.ads.mediation.MediationBannerListener mediationBannerListener) {
            this.zzaN = abstractAdViewAdapter;
            this.zzaO = mediationBannerListener;
        }

        @Override // com.google.android.gms.ads.internal.client.zza
        public void onAdClicked() {
            this.zzaO.onAdClicked(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdClosed() {
            this.zzaO.onAdClosed(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdFailedToLoad(int errorCode) {
            this.zzaO.onAdFailedToLoad(this.zzaN, errorCode);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdLeftApplication() {
            this.zzaO.onAdLeftApplication(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdLoaded() {
            this.zzaO.onAdLoaded(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdOpened() {
            this.zzaO.onAdOpened(this.zzaN);
        }
    }

    /* loaded from: classes.dex */
    static final class zzb extends AdListener implements com.google.android.gms.ads.internal.client.zza {
        final AbstractAdViewAdapter zzaN;
        final com.google.android.gms.ads.mediation.MediationInterstitialListener zzaP;

        public zzb(AbstractAdViewAdapter abstractAdViewAdapter, com.google.android.gms.ads.mediation.MediationInterstitialListener mediationInterstitialListener) {
            this.zzaN = abstractAdViewAdapter;
            this.zzaP = mediationInterstitialListener;
        }

        @Override // com.google.android.gms.ads.internal.client.zza
        public void onAdClicked() {
            this.zzaP.onAdClicked(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdClosed() {
            this.zzaP.onAdClosed(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdFailedToLoad(int errorCode) {
            this.zzaP.onAdFailedToLoad(this.zzaN, errorCode);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdLeftApplication() {
            this.zzaP.onAdLeftApplication(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdLoaded() {
            this.zzaP.onAdLoaded(this.zzaN);
        }

        @Override // com.google.android.gms.ads.AdListener
        public void onAdOpened() {
            this.zzaP.onAdOpened(this.zzaN);
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter
    public View getBannerView() {
        return this.zzaL;
    }

    @Override // com.google.android.gms.ads.mediation.MediationAdapter
    public void onDestroy() {
        if (this.zzaL != null) {
            this.zzaL.destroy();
            this.zzaL = null;
        }
        if (this.zzaM != null) {
            this.zzaM = null;
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationAdapter
    public void onPause() {
        if (this.zzaL != null) {
            this.zzaL.pause();
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationAdapter
    public void onResume() {
        if (this.zzaL != null) {
            this.zzaL.resume();
        }
    }

    @Override // com.google.android.gms.ads.mediation.MediationBannerAdapter
    public void requestBannerAd(Context context, com.google.android.gms.ads.mediation.MediationBannerListener bannerListener, Bundle serverParameters, AdSize adSize, com.google.android.gms.ads.mediation.MediationAdRequest mediationAdRequest, Bundle extras) {
        this.zzaL = new AdView(context);
        this.zzaL.setAdSize(new AdSize(adSize.getWidth(), adSize.getHeight()));
        this.zzaL.setAdUnitId(serverParameters.getString(AD_UNIT_ID_PARAMETER));
        this.zzaL.setAdListener(new zza(this, bannerListener));
        this.zzaL.loadAd(zza(context, mediationAdRequest, extras, serverParameters));
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter
    public void requestInterstitialAd(Context context, com.google.android.gms.ads.mediation.MediationInterstitialListener interstitialListener, Bundle serverParameters, com.google.android.gms.ads.mediation.MediationAdRequest mediationAdRequest, Bundle extras) {
        this.zzaM = new InterstitialAd(context);
        this.zzaM.setAdUnitId(serverParameters.getString(AD_UNIT_ID_PARAMETER));
        this.zzaM.setAdListener(new zzb(this, interstitialListener));
        this.zzaM.loadAd(zza(context, mediationAdRequest, extras, serverParameters));
    }

    @Override // com.google.android.gms.ads.mediation.MediationInterstitialAdapter
    public void showInterstitial() {
        this.zzaM.show();
    }

    protected abstract Bundle zza(Bundle bundle, Bundle bundle2);

    AdRequest zza(Context context, com.google.android.gms.ads.mediation.MediationAdRequest mediationAdRequest, Bundle bundle, Bundle bundle2) {
        AdRequest.Builder builder = new AdRequest.Builder();
        Date birthday = mediationAdRequest.getBirthday();
        if (birthday != null) {
            builder.setBirthday(birthday);
        }
        int gender = mediationAdRequest.getGender();
        if (gender != 0) {
            builder.setGender(gender);
        }
        Set<String> keywords = mediationAdRequest.getKeywords();
        if (keywords != null) {
            for (String str : keywords) {
                builder.addKeyword(str);
            }
        }
        Location location = mediationAdRequest.getLocation();
        if (location != null) {
            builder.setLocation(location);
        }
        if (mediationAdRequest.isTesting()) {
            builder.addTestDevice(zzk.zzcA().zzO(context));
        }
        if (mediationAdRequest.taggedForChildDirectedTreatment() != -1) {
            builder.tagForChildDirectedTreatment(mediationAdRequest.taggedForChildDirectedTreatment() == 1);
        }
        builder.addNetworkExtrasBundle(AdMobAdapter.class, zza(bundle, bundle2));
        return builder.build();
    }
}
