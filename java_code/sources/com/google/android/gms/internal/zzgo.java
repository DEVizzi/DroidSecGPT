package com.google.android.gms.internal;

import android.content.Context;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.reward.client.RewardedVideoAdRequestParcel;
import com.google.android.gms.ads.internal.reward.mediation.client.RewardItemParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzha;
import java.util.HashMap;
@zzgd
/* loaded from: classes.dex */
public class zzgo extends com.google.android.gms.ads.internal.zzb implements zzgs {
    private com.google.android.gms.ads.internal.reward.client.zzd zzEN;
    private String zzEO;
    private boolean zzEP;
    private HashMap<String, zzgp> zzEQ;

    public zzgo(Context context, AdSizeParcel adSizeParcel, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        super(context, adSizeParcel, null, zzefVar, versionInfoParcel);
        this.zzEQ = new HashMap<>();
    }

    @Override // com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void destroy() {
        com.google.android.gms.common.internal.zzu.zzbY("destroy must be called on the main UI thread.");
        for (String str : this.zzEQ.keySet()) {
            try {
                zzgp zzgpVar = this.zzEQ.get(str);
                if (zzgpVar != null && zzgpVar.zzfM() != null) {
                    zzgpVar.zzfM().destroy();
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to destroy adapter: " + str);
            }
        }
    }

    public boolean isLoaded() {
        com.google.android.gms.common.internal.zzu.zzbY("isLoaded must be called on the main UI thread.");
        return this.zzon.zzpL == null && this.zzon.zzpM == null && this.zzon.zzpO != null;
    }

    @Override // com.google.android.gms.internal.zzgs
    public void onRewardedVideoAdClosed() {
        if (this.zzEN == null) {
            return;
        }
        try {
            this.zzEN.onRewardedVideoAdClosed();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onAdClosed().", e);
        }
    }

    @Override // com.google.android.gms.internal.zzgs
    public void onRewardedVideoAdLeftApplication() {
        if (this.zzEN == null) {
            return;
        }
        try {
            this.zzEN.onRewardedVideoAdLeftApplication();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onAdLeftApplication().", e);
        }
    }

    @Override // com.google.android.gms.internal.zzgs
    public void onRewardedVideoAdOpened() {
        recordImpression();
        if (this.zzEN == null) {
            return;
        }
        try {
            this.zzEN.onRewardedVideoAdOpened();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onAdOpened().", e);
        }
    }

    @Override // com.google.android.gms.internal.zzgs
    public void onRewardedVideoStarted() {
        com.google.android.gms.ads.internal.zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, this.zzon.zzpO, this.zzon.zzpG, false, this.zzon.zzpO.zzxZ.zzxB);
        if (this.zzEN == null) {
            return;
        }
        try {
            this.zzEN.onRewardedVideoStarted();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onVideoStarted().", e);
        }
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void pause() {
        com.google.android.gms.common.internal.zzu.zzbY("pause must be called on the main UI thread.");
        for (String str : this.zzEQ.keySet()) {
            try {
                zzgp zzgpVar = this.zzEQ.get(str);
                if (zzgpVar != null && zzgpVar.zzfM() != null) {
                    zzgpVar.zzfM().pause();
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to pause adapter: " + str);
            }
        }
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza, com.google.android.gms.ads.internal.client.zzr
    public void resume() {
        com.google.android.gms.common.internal.zzu.zzbY("resume must be called on the main UI thread.");
        for (String str : this.zzEQ.keySet()) {
            try {
                zzgp zzgpVar = this.zzEQ.get(str);
                if (zzgpVar != null && zzgpVar.zzfM() != null) {
                    zzgpVar.zzfM().resume();
                }
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to resume adapter: " + str);
            }
        }
    }

    public void setUserId(String userId) {
        com.google.android.gms.common.internal.zzu.zzbY("setUserId must be called on the main UI thread.");
        this.zzEO = userId;
    }

    public void zza(RewardedVideoAdRequestParcel rewardedVideoAdRequestParcel) {
        com.google.android.gms.common.internal.zzu.zzbY("loadAd must be called on the main UI thread.");
        if (TextUtils.isEmpty(rewardedVideoAdRequestParcel.zzpG)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Invalid ad unit id. Aborting.");
            return;
        }
        this.zzEP = false;
        this.zzon.zzpG = rewardedVideoAdRequestParcel.zzpG;
        super.zza(rewardedVideoAdRequestParcel.zzCm);
    }

    public void zza(com.google.android.gms.ads.internal.reward.client.zzd zzdVar) {
        com.google.android.gms.common.internal.zzu.zzbY("setRewardedVideoAdListener must be called on the main UI thread.");
        this.zzEN = zzdVar;
    }

    @Override // com.google.android.gms.internal.zzgs
    public void zza(RewardItemParcel rewardItemParcel) {
        com.google.android.gms.ads.internal.zzo.zzbG().zza(this.zzon.zzpH, this.zzon.zzpJ.zzGG, this.zzon.zzpO, this.zzon.zzpG, false, this.zzon.zzpO.zzxZ.zzxC);
        if (this.zzEN == null) {
            return;
        }
        try {
            if (this.zzon.zzpO == null || this.zzon.zzpO.zzFm == null || TextUtils.isEmpty(this.zzon.zzpO.zzFm.zzxK)) {
                this.zzEN.zza(new zzgm(rewardItemParcel.type, rewardItemParcel.zzFk));
            } else {
                this.zzEN.zza(new zzgm(this.zzon.zzpO.zzFm.zzxK, this.zzon.zzpO.zzFm.zzxL));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onRewarded().", e);
        }
    }

    @Override // com.google.android.gms.ads.internal.zzb, com.google.android.gms.ads.internal.zza
    public boolean zza(zzha zzhaVar, zzha zzhaVar2) {
        if (this.zzEN != null) {
            try {
                this.zzEN.onRewardedVideoAdLoaded();
                return true;
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onAdLoaded().", e);
                return true;
            }
        }
        return true;
    }

    public zzgp zzao(String str) {
        zzgp zzgpVar;
        zzgp zzgpVar2 = this.zzEQ.get(str);
        if (zzgpVar2 == null) {
            try {
                zzgpVar = new zzgp(this.zzoq.zzY(str), this);
            } catch (Exception e) {
                e = e;
            }
            try {
                this.zzEQ.put(str, zzgpVar);
                return zzgpVar;
            } catch (Exception e2) {
                zzgpVar2 = zzgpVar;
                e = e2;
                com.google.android.gms.ads.internal.util.client.zzb.zzd("Fail to instantiate adapter " + str, e);
                return zzgpVar2;
            }
        }
        return zzgpVar2;
    }

    @Override // com.google.android.gms.ads.internal.zza
    public boolean zzb(zzha.zza zzaVar) {
        if (zzaVar.errorCode != -2) {
            zzb(new zzha(zzaVar, null, null, null, null, null, null));
        } else {
            this.zzon.zzqh = 0;
            this.zzon.zzpM = new zzgv(this.zzon.zzpH, this.zzEO, zzaVar, this);
            this.zzon.zzpM.zzgi();
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.ads.internal.zza
    public boolean zze(int i) {
        com.google.android.gms.ads.internal.util.client.zzb.zzaC("Failed to load ad: " + i);
        if (this.zzEN == null) {
            return false;
        }
        try {
            this.zzEN.onRewardedVideoAdFailedToLoad(i);
            return true;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call RewardedVideoAdListener.onAdFailedToLoad().", e);
            return false;
        }
    }

    public void zzfK() {
        com.google.android.gms.common.internal.zzu.zzbY("showAd must be called on the main UI thread.");
        if (!isLoaded() || this.zzEP) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("The reward video has not loaded.");
            return;
        }
        this.zzEP = true;
        zzgp zzao = zzao(this.zzon.zzpO.zzyb);
        if (zzao == null || zzao.zzfM() == null) {
            return;
        }
        try {
            zzao.zzfM().showVideo();
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not call showVideo.", e);
        }
    }

    @Override // com.google.android.gms.internal.zzgs
    public void zzfL() {
        onAdClicked();
    }
}
