package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class UntrashResourceRequest implements SafeParcelable {
    public static final Parcelable.Creator<UntrashResourceRequest> CREATOR = new zzbt();
    final int zzCY;
    final DriveId zzaeq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UntrashResourceRequest(int versionCode, DriveId id) {
        this.zzCY = versionCode;
        this.zzaeq = id;
    }

    public UntrashResourceRequest(DriveId id) {
        this(1, id);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbt.zza(this, dest, flags);
    }
}
