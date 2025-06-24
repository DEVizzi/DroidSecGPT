package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.ads.AdRequest;
import com.google.ads.mediation.MediationBannerAdapter;
import com.google.ads.mediation.MediationBannerListener;
import com.google.ads.mediation.MediationInterstitialAdapter;
import com.google.ads.mediation.MediationInterstitialListener;
import com.google.ads.mediation.MediationServerParameters;
import com.google.ads.mediation.NetworkExtras;
@zzgd
/* loaded from: classes.dex */
public final class zzem<NETWORK_EXTRAS extends NetworkExtras, SERVER_PARAMETERS extends MediationServerParameters> implements MediationBannerListener, MediationInterstitialListener {
    private final zzeh zzyg;

    public zzem(zzeh zzehVar) {
        this.zzyg = zzehVar;
    }

    @Override // com.google.ads.mediation.MediationBannerListener
    public void onClick(MediationBannerAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onClick.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onClick must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.1
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdClicked();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdClicked.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdClicked();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdClicked.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationBannerListener
    public void onDismissScreen(MediationBannerAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onDismissScreen.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onDismissScreen must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.4
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdClosed();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdClosed.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdClosed();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdClosed.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationInterstitialListener
    public void onDismissScreen(MediationInterstitialAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onDismissScreen.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onDismissScreen must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.9
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdClosed();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdClosed.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdClosed();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdClosed.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationBannerListener
    public void onFailedToReceiveAd(MediationBannerAdapter<?, ?> adapter, final AdRequest.ErrorCode errorCode) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onFailedToReceiveAd with error. " + errorCode);
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onFailedToReceiveAd must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.5
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdFailedToLoad(zzen.zza(errorCode));
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdFailedToLoad.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdFailedToLoad(zzen.zza(errorCode));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdFailedToLoad.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationInterstitialListener
    public void onFailedToReceiveAd(MediationInterstitialAdapter<?, ?> adapter, final AdRequest.ErrorCode errorCode) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onFailedToReceiveAd with error " + errorCode + ".");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onFailedToReceiveAd must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.10
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdFailedToLoad(zzen.zza(errorCode));
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdFailedToLoad.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdFailedToLoad(zzen.zza(errorCode));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdFailedToLoad.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationBannerListener
    public void onLeaveApplication(MediationBannerAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onLeaveApplication.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onLeaveApplication must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.6
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdLeftApplication();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLeftApplication.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdLeftApplication();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLeftApplication.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationInterstitialListener
    public void onLeaveApplication(MediationInterstitialAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onLeaveApplication.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onLeaveApplication must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.11
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdLeftApplication();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLeftApplication.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdLeftApplication();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLeftApplication.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationBannerListener
    public void onPresentScreen(MediationBannerAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onPresentScreen.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onPresentScreen must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.7
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdOpened();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdOpened.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdOpened();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdOpened.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationInterstitialListener
    public void onPresentScreen(MediationInterstitialAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onPresentScreen.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onPresentScreen must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.2
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdOpened();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdOpened.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdOpened();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdOpened.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationBannerListener
    public void onReceivedAd(MediationBannerAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onReceivedAd.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onReceivedAd must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.8
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdLoaded();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLoaded.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdLoaded();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLoaded.", e);
        }
    }

    @Override // com.google.ads.mediation.MediationInterstitialListener
    public void onReceivedAd(MediationInterstitialAdapter<?, ?> adapter) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Adapter called onReceivedAd.");
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzgw()) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("onReceivedAd must be called on the main UI thread.");
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.internal.zzem.3
                @Override // java.lang.Runnable
                public void run() {
                    try {
                        zzem.this.zzyg.onAdLoaded();
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLoaded.", e);
                    }
                }
            });
            return;
        }
        try {
            this.zzyg.onAdLoaded();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call onAdLoaded.", e);
        }
    }
}
