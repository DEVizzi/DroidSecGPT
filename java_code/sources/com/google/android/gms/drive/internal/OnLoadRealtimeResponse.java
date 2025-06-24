package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class OnLoadRealtimeResponse implements SafeParcelable {
    public static final Parcelable.Creator<OnLoadRealtimeResponse> CREATOR = new zzbe();
    final int zzCY;
    final boolean zzpb;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OnLoadRealtimeResponse(int versionCode, boolean isInitialized) {
        this.zzCY = versionCode;
        this.zzpb = isInitialized;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbe.zza(this, dest, flags);
    }
}
