package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.ads.internal.client.AdSizeParcel;
import com.google.android.gms.ads.internal.reward.client.RewardedVideoAdRequestParcel;
import com.google.android.gms.ads.internal.reward.client.zzb;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
/* loaded from: classes.dex */
public class zzgn extends zzb.zza {
    private final Context mContext;
    private final zzgo zzEM;
    private final VersionInfoParcel zzoM;
    private final Object zzqt = new Object();

    public zzgn(Context context, zzef zzefVar, VersionInfoParcel versionInfoParcel) {
        this.mContext = context;
        this.zzoM = versionInfoParcel;
        this.zzEM = new zzgo(context, AdSizeParcel.zzcx(), zzefVar, versionInfoParcel);
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void destroy() {
        synchronized (this.zzqt) {
            this.zzEM.destroy();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public boolean isLoaded() {
        boolean isLoaded;
        synchronized (this.zzqt) {
            isLoaded = this.zzEM.isLoaded();
        }
        return isLoaded;
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void pause() {
        synchronized (this.zzqt) {
            this.zzEM.pause();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void resume() {
        synchronized (this.zzqt) {
            this.zzEM.resume();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void setUserId(String userId) {
        synchronized (this.zzqt) {
            this.zzEM.setUserId(userId);
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void show() {
        synchronized (this.zzqt) {
            this.zzEM.zzfK();
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void zza(RewardedVideoAdRequestParcel rewardedVideoAdRequestParcel) {
        synchronized (this.zzqt) {
            this.zzEM.zza(rewardedVideoAdRequestParcel);
        }
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zzb
    public void zza(com.google.android.gms.ads.internal.reward.client.zzd zzdVar) {
        synchronized (this.zzqt) {
            this.zzEM.zza(zzdVar);
        }
    }
}
