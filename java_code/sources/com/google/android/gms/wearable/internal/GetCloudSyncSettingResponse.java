package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class GetCloudSyncSettingResponse implements SafeParcelable {
    public static final Parcelable.Creator<GetCloudSyncSettingResponse> CREATOR = new zzaj();
    public final boolean enabled;
    public final int statusCode;
    public final int versionCode;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GetCloudSyncSettingResponse(int versionCode, int statusCode, boolean enabled) {
        this.versionCode = versionCode;
        this.statusCode = statusCode;
        this.enabled = enabled;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzaj.zza(this, dest, flags);
    }
}
