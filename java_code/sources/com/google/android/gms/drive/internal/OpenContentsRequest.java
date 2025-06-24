package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class OpenContentsRequest implements SafeParcelable {
    public static final Parcelable.Creator<OpenContentsRequest> CREATOR = new zzbh();
    final int zzCY;
    final int zzacS;
    final DriveId zzaeq;
    final int zzagr;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OpenContentsRequest(int versionCode, DriveId id, int mode, int baseRequestId) {
        this.zzCY = versionCode;
        this.zzaeq = id;
        this.zzacS = mode;
        this.zzagr = baseRequestId;
    }

    public OpenContentsRequest(DriveId id, int mode, int baseRequestId) {
        this(1, id, mode, baseRequestId);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbh.zza(this, dest, flags);
    }
}
