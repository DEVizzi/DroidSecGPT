package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.List;
/* loaded from: classes.dex */
public class GetAllCapabilitiesResponse implements SafeParcelable {
    public static final Parcelable.Creator<GetAllCapabilitiesResponse> CREATOR = new zzae();
    public final int statusCode;
    public final int versionCode;
    final List<CapabilityInfoParcelable> zzaUq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GetAllCapabilitiesResponse(int versionCode, int statusCode, List<CapabilityInfoParcelable> capabilities) {
        this.versionCode = versionCode;
        this.statusCode = statusCode;
        this.zzaUq = capabilities;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzae.zza(this, dest, flags);
    }
}
