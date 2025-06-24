package com.google.android.gms.ads.internal.client;

import android.location.Location;
import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzgd;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public final class AdRequestParcel implements SafeParcelable {
    public static final zzf CREATOR = new zzf();
    public final Bundle extras;
    public final int versionCode;
    public final long zzrX;
    public final int zzrY;
    public final List<String> zzrZ;
    public final boolean zzsa;
    public final int zzsb;
    public final boolean zzsc;
    public final String zzsd;
    public final SearchAdRequestParcel zzse;
    public final Location zzsf;
    public final String zzsg;
    public final Bundle zzsh;
    public final Bundle zzsi;
    public final List<String> zzsj;
    public final String zzsk;

    public AdRequestParcel(int versionCode, long birthday, Bundle extras, int gender, List<String> keywords, boolean isTestDevice, int tagForChildDirectedTreatment, boolean manualImpressionsEnabled, String publisherProvidedId, SearchAdRequestParcel searchAdRequestParcel, Location location, String contentUrl, Bundle networkExtras, Bundle customTargeting, List<String> categoryExclusions, String requestAgent) {
        this.versionCode = versionCode;
        this.zzrX = birthday;
        this.extras = extras == null ? new Bundle() : extras;
        this.zzrY = gender;
        this.zzrZ = keywords;
        this.zzsa = isTestDevice;
        this.zzsb = tagForChildDirectedTreatment;
        this.zzsc = manualImpressionsEnabled;
        this.zzsd = publisherProvidedId;
        this.zzse = searchAdRequestParcel;
        this.zzsf = location;
        this.zzsg = contentUrl;
        this.zzsh = networkExtras;
        this.zzsi = customTargeting;
        this.zzsj = categoryExclusions;
        this.zzsk = requestAgent;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzf.zza(this, out, flags);
    }
}
