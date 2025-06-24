package com.google.android.gms.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.ads.mediation.admob.AdMobAdapter;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.mediation.MediationAdapter;
import com.google.android.gms.ads.mediation.MediationBannerAdapter;
import com.google.android.gms.ads.mediation.MediationInterstitialAdapter;
import com.google.android.gms.ads.reward.mediation.MediationRewardedVideoAdAdapter;
import com.google.android.gms.internal.zzeg;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public final class zzej extends zzeg.zza {
    private final MediationAdapter zzyf;

    public zzej(MediationAdapter mediationAdapter) {
        this.zzyf = mediationAdapter;
    }

    private Bundle zza(String str, int i, String str2) throws RemoteException {
        com.google.android.gms.ads.internal.util.client.zzb.zzaC("Server parameters: " + str);
        try {
            Bundle bundle = new Bundle();
            if (str != null) {
                JSONObject jSONObject = new JSONObject(str);
                Bundle bundle2 = new Bundle();
                Iterator<String> keys = jSONObject.keys();
                while (keys.hasNext()) {
                    String next = keys.next();
                    bundle2.putString(next, jSONObject.getString(next));
                }
                bundle = bundle2;
            }
            if (this.zzyf instanceof AdMobAdapter) {
                bundle.putString("adJson", str2);
                bundle.putInt("tagForChildDirectedTreatment", i);
            }
            return bundle;
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get Server Parameters Bundle.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void destroy() throws RemoteException {
        try {
            this.zzyf.onDestroy();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not destroy adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public com.google.android.gms.dynamic.zzd getView() throws RemoteException {
        if (!(this.zzyf instanceof MediationBannerAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationBannerAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        try {
            return com.google.android.gms.dynamic.zze.zzw(((MediationBannerAdapter) this.zzyf).getBannerView());
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get banner view from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public boolean isInitialized() throws RemoteException {
        if (!(this.zzyf instanceof MediationRewardedVideoAdAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationRewardedVideoAdAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Check if adapter is initialized.");
        try {
            return ((MediationRewardedVideoAdAdapter) this.zzyf).isInitialized();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not check if adapter is initialized.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void pause() throws RemoteException {
        try {
            this.zzyf.onPause();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not pause adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void resume() throws RemoteException {
        try {
            this.zzyf.onResume();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not resume adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void showInterstitial() throws RemoteException {
        if (!(this.zzyf instanceof MediationInterstitialAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationInterstitialAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Showing interstitial from adapter.");
        try {
            ((MediationInterstitialAdapter) this.zzyf).showInterstitial();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not show interstitial from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void showVideo() throws RemoteException {
        if (!(this.zzyf instanceof MediationRewardedVideoAdAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationRewardedVideoAdAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Show rewarded video ad from adapter.");
        try {
            ((MediationRewardedVideoAdAdapter) this.zzyf).showVideo();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not show rewarded video ad from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(AdRequestParcel adRequestParcel, String str) throws RemoteException {
        if (!(this.zzyf instanceof MediationRewardedVideoAdAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationRewardedVideoAdAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Requesting rewarded video ad from adapter.");
        try {
            MediationRewardedVideoAdAdapter mediationRewardedVideoAdAdapter = (MediationRewardedVideoAdAdapter) this.zzyf;
            mediationRewardedVideoAdAdapter.loadAd(new zzei(adRequestParcel.zzrX == -1 ? null : new Date(adRequestParcel.zzrX), adRequestParcel.zzrY, adRequestParcel.zzrZ != null ? new HashSet(adRequestParcel.zzrZ) : null, adRequestParcel.zzsf, adRequestParcel.zzsa, adRequestParcel.zzsb), zza(str, adRequestParcel.zzsb, null), adRequestParcel.zzsh != null ? adRequestParcel.zzsh.getBundle(mediationRewardedVideoAdAdapter.getClass().getName()) : null);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not load rewarded video ad from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdRequestParcel adRequestParcel, String str, com.google.android.gms.ads.internal.reward.mediation.client.zza zzaVar, String str2) throws RemoteException {
        if (!(this.zzyf instanceof MediationRewardedVideoAdAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationRewardedVideoAdAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Initialize rewarded video adapter.");
        try {
            MediationRewardedVideoAdAdapter mediationRewardedVideoAdAdapter = (MediationRewardedVideoAdAdapter) this.zzyf;
            mediationRewardedVideoAdAdapter.initialize((Context) com.google.android.gms.dynamic.zze.zzn(zzdVar), new zzei(adRequestParcel.zzrX == -1 ? null : new Date(adRequestParcel.zzrX), adRequestParcel.zzrY, adRequestParcel.zzrZ != null ? new HashSet(adRequestParcel.zzrZ) : null, adRequestParcel.zzsf, adRequestParcel.zzsa, adRequestParcel.zzsb), str, new com.google.android.gms.ads.internal.reward.mediation.client.zzb(zzaVar), zza(str2, adRequestParcel.zzsb, null), adRequestParcel.zzsh != null ? adRequestParcel.zzsh.getBundle(mediationRewardedVideoAdAdapter.getClass().getName()) : null);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not initialize rewarded video adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdRequestParcel adRequestParcel, String str, zzeh zzehVar) throws RemoteException {
        zza(zzdVar, adRequestParcel, str, (String) null, zzehVar);
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdRequestParcel adRequestParcel, String str, String str2, zzeh zzehVar) throws RemoteException {
        if (!(this.zzyf instanceof MediationInterstitialAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationInterstitialAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Requesting interstitial ad from adapter.");
        try {
            MediationInterstitialAdapter mediationInterstitialAdapter = (MediationInterstitialAdapter) this.zzyf;
            mediationInterstitialAdapter.requestInterstitialAd((Context) com.google.android.gms.dynamic.zze.zzn(zzdVar), new zzek(zzehVar), zza(str, adRequestParcel.zzsb, str2), new zzei(adRequestParcel.zzrX == -1 ? null : new Date(adRequestParcel.zzrX), adRequestParcel.zzrY, adRequestParcel.zzrZ != null ? new HashSet(adRequestParcel.zzrZ) : null, adRequestParcel.zzsf, adRequestParcel.zzsa, adRequestParcel.zzsb), adRequestParcel.zzsh != null ? adRequestParcel.zzsh.getBundle(mediationInterstitialAdapter.getClass().getName()) : null);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not request interstitial ad from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdSizeParcel adSizeParcel, AdRequestParcel adRequestParcel, String str, zzeh zzehVar) throws RemoteException {
        zza(zzdVar, adSizeParcel, adRequestParcel, str, null, zzehVar);
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdSizeParcel adSizeParcel, AdRequestParcel adRequestParcel, String str, String str2, zzeh zzehVar) throws RemoteException {
        if (!(this.zzyf instanceof MediationBannerAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationBannerAdapter: " + this.zzyf.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Requesting banner ad from adapter.");
        try {
            MediationBannerAdapter mediationBannerAdapter = (MediationBannerAdapter) this.zzyf;
            mediationBannerAdapter.requestBannerAd((Context) com.google.android.gms.dynamic.zze.zzn(zzdVar), new zzek(zzehVar), zza(str, adRequestParcel.zzsb, str2), com.google.android.gms.ads.zza.zza(adSizeParcel.width, adSizeParcel.height, adSizeParcel.zzsm), new zzei(adRequestParcel.zzrX == -1 ? null : new Date(adRequestParcel.zzrX), adRequestParcel.zzrY, adRequestParcel.zzrZ != null ? new HashSet(adRequestParcel.zzrZ) : null, adRequestParcel.zzsf, adRequestParcel.zzsa, adRequestParcel.zzsb), adRequestParcel.zzsh != null ? adRequestParcel.zzsh.getBundle(mediationBannerAdapter.getClass().getName()) : null);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not request banner ad from adapter.", th);
            throw new RemoteException();
        }
    }
}
