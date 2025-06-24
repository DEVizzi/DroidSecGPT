package com.google.android.gms.internal;

import com.google.android.gms.ads.internal.reward.mediation.client.RewardItemParcel;
import com.google.android.gms.ads.internal.reward.mediation.client.zza;
@zzgd
/* loaded from: classes.dex */
public class zzgt extends zza.AbstractBinderC0023zza {
    private zzgu zzEW;
    private zzgr zzFc;
    private zzgs zzFd;

    public zzgt(zzgs zzgsVar) {
        this.zzFd = zzgsVar;
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zza(com.google.android.gms.dynamic.zzd zzdVar, RewardItemParcel rewardItemParcel) {
        if (this.zzFd != null) {
            this.zzFd.zza(rewardItemParcel);
        }
    }

    public void zza(zzgr zzgrVar) {
        this.zzFc = zzgrVar;
    }

    public void zza(zzgu zzguVar) {
        this.zzEW = zzguVar;
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzb(com.google.android.gms.dynamic.zzd zzdVar, int i) {
        if (this.zzFc != null) {
            this.zzFc.zzI(i);
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzc(com.google.android.gms.dynamic.zzd zzdVar, int i) {
        if (this.zzEW != null) {
            this.zzEW.zzb(com.google.android.gms.dynamic.zze.zzn(zzdVar).getClass().getName(), i);
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zze(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzFc != null) {
            this.zzFc.zzfO();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzf(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzEW != null) {
            this.zzEW.zzap(com.google.android.gms.dynamic.zze.zzn(zzdVar).getClass().getName());
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzg(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzFd != null) {
            this.zzFd.onRewardedVideoAdOpened();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzh(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzFd != null) {
            this.zzFd.onRewardedVideoStarted();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzi(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzFd != null) {
            this.zzFd.onRewardedVideoAdClosed();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzj(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzFd != null) {
            this.zzFd.zzfL();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.mediation.client.zza
    public void zzk(com.google.android.gms.dynamic.zzd zzdVar) {
        if (this.zzFd != null) {
            this.zzFd.onRewardedVideoAdLeftApplication();
        }
    }
}
