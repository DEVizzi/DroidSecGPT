package com.google.android.gms.internal;

import android.app.Activity;
import android.os.RemoteException;
import com.google.ads.mediation.MediationAdapter;
import com.google.ads.mediation.MediationBannerAdapter;
import com.google.ads.mediation.MediationInterstitialAdapter;
import com.google.ads.mediation.MediationServerParameters;
import com.google.ads.mediation.NetworkExtras;
import com.google.android.gms.ads.internal.client.AdRequestParcel;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.internal.zzeg;
import java.util.HashMap;
import java.util.Iterator;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public final class zzel<NETWORK_EXTRAS extends NetworkExtras, SERVER_PARAMETERS extends MediationServerParameters> extends zzeg.zza {
    private final MediationAdapter<NETWORK_EXTRAS, SERVER_PARAMETERS> zzyh;
    private final NETWORK_EXTRAS zzyi;

    public zzel(MediationAdapter<NETWORK_EXTRAS, SERVER_PARAMETERS> mediationAdapter, NETWORK_EXTRAS network_extras) {
        this.zzyh = mediationAdapter;
        this.zzyi = network_extras;
    }

    private SERVER_PARAMETERS zzb(String str, int i, String str2) throws RemoteException {
        HashMap hashMap;
        try {
            if (str != null) {
                JSONObject jSONObject = new JSONObject(str);
                hashMap = new HashMap(jSONObject.length());
                Iterator<String> keys = jSONObject.keys();
                while (keys.hasNext()) {
                    String next = keys.next();
                    hashMap.put(next, jSONObject.getString(next));
                }
            } else {
                hashMap = new HashMap(0);
            }
            Class<SERVER_PARAMETERS> serverParametersType = this.zzyh.getServerParametersType();
            if (serverParametersType != null) {
                SERVER_PARAMETERS newInstance = serverParametersType.newInstance();
                newInstance.load(hashMap);
                return newInstance;
            }
            return null;
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get MediationServerParameters.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void destroy() throws RemoteException {
        try {
            this.zzyh.destroy();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not destroy adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public com.google.android.gms.dynamic.zzd getView() throws RemoteException {
        if (!(this.zzyh instanceof MediationBannerAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationBannerAdapter: " + this.zzyh.getClass().getCanonicalName());
            throw new RemoteException();
        }
        try {
            return com.google.android.gms.dynamic.zze.zzw(((MediationBannerAdapter) this.zzyh).getBannerView());
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get banner view from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public boolean isInitialized() {
        return true;
    }

    @Override // com.google.android.gms.internal.zzeg
    public void pause() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.zzeg
    public void resume() throws RemoteException {
        throw new RemoteException();
    }

    @Override // com.google.android.gms.internal.zzeg
    public void showInterstitial() throws RemoteException {
        if (!(this.zzyh instanceof MediationInterstitialAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationInterstitialAdapter: " + this.zzyh.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Showing interstitial from adapter.");
        try {
            ((MediationInterstitialAdapter) this.zzyh).showInterstitial();
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not show interstitial from adapter.", th);
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzeg
    public void showVideo() {
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(AdRequestParcel adRequestParcel, String str) {
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdRequestParcel adRequestParcel, String str, com.google.android.gms.ads.internal.reward.mediation.client.zza zzaVar, String str2) throws RemoteException {
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdRequestParcel adRequestParcel, String str, zzeh zzehVar) throws RemoteException {
        zza(zzdVar, adRequestParcel, str, (String) null, zzehVar);
    }

    @Override // com.google.android.gms.internal.zzeg
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, AdRequestParcel adRequestParcel, String str, String str2, zzeh zzehVar) throws RemoteException {
        if (!(this.zzyh instanceof MediationInterstitialAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationInterstitialAdapter: " + this.zzyh.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Requesting interstitial ad from adapter.");
        try {
            ((MediationInterstitialAdapter) this.zzyh).requestInterstitialAd(new zzem(zzehVar), (Activity) com.google.android.gms.dynamic.zze.zzn(zzdVar), zzb(str, adRequestParcel.zzsb, str2), zzen.zzg(adRequestParcel), this.zzyi);
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
        if (!(this.zzyh instanceof MediationBannerAdapter)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("MediationAdapter is not a MediationBannerAdapter: " + this.zzyh.getClass().getCanonicalName());
            throw new RemoteException();
        }
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Requesting banner ad from adapter.");
        try {
            ((MediationBannerAdapter) this.zzyh).requestBannerAd(new zzem(zzehVar), (Activity) com.google.android.gms.dynamic.zze.zzn(zzdVar), zzb(str, adRequestParcel.zzsb, str2), zzen.zzb(adSizeParcel), zzen.zzg(adRequestParcel), this.zzyi);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not request banner ad from adapter.", th);
            throw new RemoteException();
        }
    }
}
