package com.google.android.gms.drive.metadata.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.drive.metadata.CustomPropertyKey;
/* loaded from: classes.dex */
public class CustomProperty implements SafeParcelable {
    public static final Parcelable.Creator<CustomProperty> CREATOR = new zzc();
    final String mValue;
    final int zzCY;
    final CustomPropertyKey zzagG;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CustomProperty(int versionCode, CustomPropertyKey key, String value) {
        this.zzCY = versionCode;
        zzu.zzb(key, "key");
        this.zzagG = key;
        this.mValue = value;
    }

    public CustomProperty(CustomPropertyKey key, String value) {
        this(1, key, value);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getValue() {
        return this.mValue;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }

    public CustomPropertyKey zzpV() {
        return this.zzagG;
    }
}
