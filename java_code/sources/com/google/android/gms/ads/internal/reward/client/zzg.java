package com.google.android.gms.ads.internal.reward.client;

import com.google.android.gms.ads.internal.reward.client.zzd;
import com.google.android.gms.ads.reward.RewardedVideoAdListener;
/* loaded from: classes.dex */
public class zzg extends zzd.zza {
    private final RewardedVideoAdListener zzES;

    public zzg(RewardedVideoAdListener rewardedVideoAdListener) {
        this.zzES = rewardedVideoAdListener;
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void onRewardedVideoAdClosed() {
        if (this.zzES != null) {
            this.zzES.onRewardedVideoAdClosed();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void onRewardedVideoAdFailedToLoad(int errorCode) {
        if (this.zzES != null) {
            this.zzES.onRewardedVideoAdFailedToLoad(errorCode);
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void onRewardedVideoAdLeftApplication() {
        if (this.zzES != null) {
            this.zzES.onRewardedVideoAdLeftApplication();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void onRewardedVideoAdLoaded() {
        if (this.zzES != null) {
            this.zzES.onRewardedVideoAdLoaded();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void onRewardedVideoAdOpened() {
        if (this.zzES != null) {
            this.zzES.onRewardedVideoAdOpened();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void onRewardedVideoStarted() {
        if (this.zzES != null) {
            this.zzES.onRewardedVideoStarted();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzd
    public void zza(zza zzaVar) {
        if (this.zzES != null) {
            this.zzES.onRewarded(new zze(zzaVar));
        }
    }
}
