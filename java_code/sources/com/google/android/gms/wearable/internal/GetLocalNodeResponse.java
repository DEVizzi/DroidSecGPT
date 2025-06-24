package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class GetLocalNodeResponse implements SafeParcelable {
    public static final Parcelable.Creator<GetLocalNodeResponse> CREATOR = new zzap();
    public final int statusCode;
    public final int versionCode;
    public final NodeParcelable zzaUz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GetLocalNodeResponse(int versionCode, int statusCode, NodeParcelable node) {
        this.versionCode = versionCode;
        this.statusCode = statusCode;
        this.zzaUz = node;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzap.zza(this, dest, flags);
    }
}
