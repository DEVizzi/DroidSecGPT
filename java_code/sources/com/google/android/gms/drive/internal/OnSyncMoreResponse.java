package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class OnSyncMoreResponse implements SafeParcelable {
    public static final Parcelable.Creator<OnSyncMoreResponse> CREATOR = new zzbg();
    final int zzCY;
    final boolean zzaeL;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OnSyncMoreResponse(int versionCode, boolean moreEntriesMayExist) {
        this.zzCY = versionCode;
        this.zzaeL = moreEntriesMayExist;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbg.zza(this, dest, flags);
    }
}
