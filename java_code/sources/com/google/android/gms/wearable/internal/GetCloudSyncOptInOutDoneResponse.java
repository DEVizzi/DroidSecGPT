package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class GetCloudSyncOptInOutDoneResponse implements SafeParcelable {
    public static final Parcelable.Creator<GetCloudSyncOptInOutDoneResponse> CREATOR = new zzai();
    public final int statusCode;
    public final int versionCode;
    public final boolean zzaUt;

    /* JADX INFO: Access modifiers changed from: package-private */
    public GetCloudSyncOptInOutDoneResponse(int versionCode, int statusCode, boolean optInOutDone) {
        this.versionCode = versionCode;
        this.statusCode = statusCode;
        this.zzaUt = optInOutDone;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzai.zza(this, dest, flags);
    }
}
