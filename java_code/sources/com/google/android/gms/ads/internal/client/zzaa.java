package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.reward.RewardedVideoAd;
import com.google.android.gms.internal.zzee;
/* loaded from: classes.dex */
public class zzaa {
    private static final Object zzoW = new Object();
    private static zzaa zzta;
    private zzv zztb;
    private RewardedVideoAd zztc;

    private zzaa() {
    }

    public static zzaa zzcP() {
        zzaa zzaaVar;
        synchronized (zzoW) {
            if (zzta == null) {
                zzta = new zzaa();
            }
            zzaaVar = zzta;
        }
        return zzaaVar;
    }

    public RewardedVideoAd getRewardedVideoAdInstance(Context context) {
        RewardedVideoAd rewardedVideoAd;
        synchronized (zzoW) {
            if (this.zztc != null) {
                rewardedVideoAd = this.zztc;
            } else {
                this.zztc = new com.google.android.gms.ads.internal.reward.client.zzi(context, zzk.zzcF().zza(context, new zzee()));
                rewardedVideoAd = this.zztc;
            }
        }
        return rewardedVideoAd;
    }

    public void zza(Context context, String str, zzab zzabVar) {
        synchronized (zzoW) {
            if (this.zztb != null) {
                return;
            }
            if (context == null) {
                throw new IllegalArgumentException("Context cannot be null.");
            }
            if (TextUtils.isEmpty(str)) {
                throw new IllegalArgumentException("applicationCode cannot be empty.");
            }
            try {
                this.zztb = zzk.zzcD().zzt(context);
                this.zztb.zza(str, zzabVar == null ? null : new MobileAdsSettingsParcel(zzabVar));
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to initialize mobile ads setting manager");
            }
        }
    }
}
