package com.google.android.gms.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.client.zzaa;
import com.google.android.gms.ads.internal.client.zzab;
import com.google.android.gms.ads.reward.RewardedVideoAd;
/* loaded from: classes.dex */
public class MobileAds {

    /* loaded from: classes.dex */
    public static final class Settings {
        private final zzab zznR = new zzab();

        public String getTrackingId() {
            return this.zznR.getTrackingId();
        }

        public boolean isGoogleAnalyticsEnabled() {
            return this.zznR.isGoogleAnalyticsEnabled();
        }

        public Settings setGoogleAnalyticsEnabled(boolean enable) {
            this.zznR.zzl(enable);
            return this;
        }

        public Settings setTrackingId(String trackingId) {
            this.zznR.zzN(trackingId);
            return this;
        }

        zzab zzaG() {
            return this.zznR;
        }
    }

    private MobileAds() {
    }

    public static RewardedVideoAd getRewardedVideoAdInstance(Context context) {
        return zzaa.zzcP().getRewardedVideoAdInstance(context);
    }

    public static void initialize(Context context, String applicationCode) {
        initialize(context, applicationCode, null);
    }

    public static void initialize(Context context, String applicationCode, Settings settings) {
        zzaa.zzcP().zza(context, applicationCode, settings == null ? null : settings.zzaG());
    }
}
