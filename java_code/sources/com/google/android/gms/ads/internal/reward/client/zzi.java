package com.google.android.gms.ads.internal.reward.client;

import android.content.Context;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.AdRequest;
import com.google.android.gms.ads.reward.RewardedVideoAd;
import com.google.android.gms.ads.reward.RewardedVideoAdListener;
/* loaded from: classes.dex */
public class zzi implements RewardedVideoAd {
    private final Context mContext;
    private String zzEO;
    private RewardedVideoAdListener zzES;
    private final zzb zzET;
    private final Object zzqt = new Object();

    public zzi(Context context, zzb zzbVar) {
        this.zzET = zzbVar;
        this.mContext = context;
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void destroy() {
        synchronized (this.zzqt) {
            if (this.zzET == null) {
                return;
            }
            try {
                this.zzET.destroy();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward destroy to RewardedVideoAd", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public RewardedVideoAdListener getRewardedVideoAdListener() {
        RewardedVideoAdListener rewardedVideoAdListener;
        synchronized (this.zzqt) {
            rewardedVideoAdListener = this.zzES;
        }
        return rewardedVideoAdListener;
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public String getUserId() {
        String str;
        synchronized (this.zzqt) {
            str = this.zzEO;
        }
        return str;
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public boolean isLoaded() {
        boolean z = false;
        synchronized (this.zzqt) {
            if (this.zzET != null) {
                try {
                    z = this.zzET.isLoaded();
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward isLoaded to RewardedVideoAd", e);
                }
            }
        }
        return z;
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void loadAd(String adUnitId, AdRequest adRequest) {
        synchronized (this.zzqt) {
            if (this.zzET == null) {
                return;
            }
            try {
                this.zzET.zza(com.google.android.gms.ads.internal.client.zzg.zzcw().zza(this.mContext, adRequest.zzaF(), adUnitId));
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward loadAd to RewardedVideoAd", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void pause() {
        synchronized (this.zzqt) {
            if (this.zzET == null) {
                return;
            }
            try {
                this.zzET.pause();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward pause to RewardedVideoAd", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void resume() {
        synchronized (this.zzqt) {
            if (this.zzET == null) {
                return;
            }
            try {
                this.zzET.resume();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward resume to RewardedVideoAd", e);
            }
        }
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void setRewardedVideoAdListener(RewardedVideoAdListener listener) {
        synchronized (this.zzqt) {
            if (this.zzES != null) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("A RewardedVideoAdListener has already been set, ignoring.");
                return;
            }
            this.zzES = listener;
            if (this.zzET != null) {
                try {
                    this.zzET.zza(new zzg(listener));
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward setRewardedVideoAdListener to RewardedVideoAd", e);
                }
            }
        }
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void setUserId(String userId) {
        synchronized (this.zzqt) {
            if (!TextUtils.isEmpty(this.zzEO)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("A user id has already been set, ignoring.");
                return;
            }
            this.zzEO = userId;
            if (this.zzET != null) {
                try {
                    this.zzET.setUserId(userId);
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward setUserId to RewardedVideoAd", e);
                }
            }
        }
    }

    @Override // com.google.android.gms.ads.reward.RewardedVideoAd
    public void show() {
        synchronized (this.zzqt) {
            if (this.zzET == null) {
                return;
            }
            try {
                this.zzET.show();
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not forward show to RewardedVideoAd", e);
            }
        }
    }
}
