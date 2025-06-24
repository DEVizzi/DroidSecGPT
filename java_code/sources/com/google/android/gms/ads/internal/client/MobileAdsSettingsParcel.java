package com.google.android.gms.ads.internal.client;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class MobileAdsSettingsParcel implements SafeParcelable {
    public static final zzad CREATOR = new zzad();
    public final int versionCode;
    public final boolean zztf;
    public final String zztg;

    public MobileAdsSettingsParcel(int versionCode, boolean isGoogleAnalyticsEnabled, String trackingId) {
        this.versionCode = versionCode;
        this.zztf = isGoogleAnalyticsEnabled;
        this.zztg = trackingId;
    }

    public MobileAdsSettingsParcel(zzab settings) {
        this(1, settings.isGoogleAnalyticsEnabled(), settings.getTrackingId());
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzad.zza(this, out, flags);
    }
}
