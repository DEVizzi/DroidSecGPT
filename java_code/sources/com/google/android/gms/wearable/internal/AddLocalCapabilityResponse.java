package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class AddLocalCapabilityResponse implements SafeParcelable {
    public static final Parcelable.Creator<AddLocalCapabilityResponse> CREATOR = new zzc();
    public final int statusCode;
    public final int versionCode;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AddLocalCapabilityResponse(int versionCode, int statusCode) {
        this.versionCode = versionCode;
        this.statusCode = statusCode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }
}
