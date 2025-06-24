package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
@Deprecated
/* loaded from: classes.dex */
public class CountrySpecification implements SafeParcelable {
    public static final Parcelable.Creator<CountrySpecification> CREATOR = new zzc();
    private final int zzCY;
    String zzEr;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CountrySpecification(int versionCode, String countryCode) {
        this.zzCY = versionCode;
        this.zzEr = countryCode;
    }

    public CountrySpecification(String countryCode) {
        this.zzCY = 1;
        this.zzEr = countryCode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getCountryCode() {
        return this.zzEr;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }
}
