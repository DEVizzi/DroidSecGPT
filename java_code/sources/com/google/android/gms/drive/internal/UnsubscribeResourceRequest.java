package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class UnsubscribeResourceRequest implements SafeParcelable {
    public static final Parcelable.Creator<UnsubscribeResourceRequest> CREATOR = new zzbs();
    final int zzCY;
    final DriveId zzaeq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UnsubscribeResourceRequest(int versionCode, DriveId id) {
        this.zzCY = versionCode;
        this.zzaeq = id;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbs.zza(this, dest, flags);
    }
}
