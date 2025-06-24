package com.google.android.gms.ads.doubleclick;

import android.content.Context;
import android.location.Location;
import android.os.Bundle;
import com.google.android.gms.ads.internal.client.zzx;
import com.google.android.gms.ads.mediation.MediationAdapter;
import com.google.android.gms.ads.mediation.NetworkExtras;
import com.google.android.gms.ads.mediation.customevent.CustomEvent;
import com.google.android.gms.common.internal.zzs;
import com.google.android.gms.common.internal.zzu;
import java.util.Date;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public final class PublisherAdRequest {
    public static final String DEVICE_ID_EMULATOR = zzx.DEVICE_ID_EMULATOR;
    public static final int ERROR_CODE_INTERNAL_ERROR = 0;
    public static final int ERROR_CODE_INVALID_REQUEST = 1;
    public static final int ERROR_CODE_NETWORK_ERROR = 2;
    public static final int ERROR_CODE_NO_FILL = 3;
    public static final int GENDER_FEMALE = 2;
    public static final int GENDER_MALE = 1;
    public static final int GENDER_UNKNOWN = 0;
    private final zzx zznK;

    /* loaded from: classes.dex */
    public static final class Builder {
        private final zzx.zza zznL = new zzx.zza();

        public Builder addCategoryExclusion(String categoryExclusion) {
            this.zznL.zzK(categoryExclusion);
            return this;
        }

        public Builder addCustomEventExtrasBundle(Class<? extends CustomEvent> adapterClass, Bundle customEventExtras) {
            this.zznL.zzb(adapterClass, customEventExtras);
            return this;
        }

        public Builder addCustomTargeting(String key, String value) {
            this.zznL.zzb(key, value);
            return this;
        }

        public Builder addCustomTargeting(String key, List<String> values) {
            if (values != null) {
                this.zznL.zzb(key, zzs.zzci(",").zza(values));
            }
            return this;
        }

        public Builder addKeyword(String keyword) {
            this.zznL.zzE(keyword);
            return this;
        }

        public Builder addNetworkExtras(NetworkExtras networkExtras) {
            this.zznL.zza(networkExtras);
            return this;
        }

        public Builder addNetworkExtrasBundle(Class<? extends MediationAdapter> adapterClass, Bundle networkExtras) {
            this.zznL.zza(adapterClass, networkExtras);
            return this;
        }

        public Builder addTestDevice(String deviceId) {
            this.zznL.zzF(deviceId);
            return this;
        }

        public PublisherAdRequest build() {
            return new PublisherAdRequest(this);
        }

        public Builder setBirthday(Date birthday) {
            this.zznL.zza(birthday);
            return this;
        }

        public Builder setContentUrl(String contentUrl) {
            zzu.zzb(contentUrl, "Content URL must be non-null.");
            zzu.zzh(contentUrl, "Content URL must be non-empty.");
            zzu.zzb(contentUrl.length() <= 512, "Content URL must not exceed %d in length.  Provided length was %d.", 512, Integer.valueOf(contentUrl.length()));
            this.zznL.zzH(contentUrl);
            return this;
        }

        public Builder setGender(int gender) {
            this.zznL.zzm(gender);
            return this;
        }

        public Builder setLocation(Location location) {
            this.zznL.zza(location);
            return this;
        }

        public Builder setManualImpressionsEnabled(boolean manualImpressionsEnabled) {
            this.zznL.zzj(manualImpressionsEnabled);
            return this;
        }

        public Builder setPublisherProvidedId(String publisherProvidedId) {
            this.zznL.zzI(publisherProvidedId);
            return this;
        }

        public Builder setRequestAgent(String requestAgent) {
            this.zznL.zzJ(requestAgent);
            return this;
        }

        public Builder tagForChildDirectedTreatment(boolean tagForChildDirectedTreatment) {
            this.zznL.zzk(tagForChildDirectedTreatment);
            return this;
        }
    }

    private PublisherAdRequest(Builder builder) {
        this.zznK = new zzx(builder.zznL);
    }

    public static void updateCorrelator() {
        zzx.updateCorrelator();
    }

    public Date getBirthday() {
        return this.zznK.getBirthday();
    }

    public String getContentUrl() {
        return this.zznK.getContentUrl();
    }

    public <T extends CustomEvent> Bundle getCustomEventExtrasBundle(Class<T> adapterClass) {
        return this.zznK.getCustomEventExtrasBundle(adapterClass);
    }

    public Bundle getCustomTargeting() {
        return this.zznK.getCustomTargeting();
    }

    public int getGender() {
        return this.zznK.getGender();
    }

    public Set<String> getKeywords() {
        return this.zznK.getKeywords();
    }

    public Location getLocation() {
        return this.zznK.getLocation();
    }

    public boolean getManualImpressionsEnabled() {
        return this.zznK.getManualImpressionsEnabled();
    }

    @Deprecated
    public <T extends NetworkExtras> T getNetworkExtras(Class<T> networkExtrasClass) {
        return (T) this.zznK.getNetworkExtras(networkExtrasClass);
    }

    public <T extends MediationAdapter> Bundle getNetworkExtrasBundle(Class<T> adapterClass) {
        return this.zznK.getNetworkExtrasBundle(adapterClass);
    }

    public String getPublisherProvidedId() {
        return this.zznK.getPublisherProvidedId();
    }

    public boolean isTestDevice(Context context) {
        return this.zznK.isTestDevice(context);
    }

    public zzx zzaF() {
        return this.zznK;
    }
}
