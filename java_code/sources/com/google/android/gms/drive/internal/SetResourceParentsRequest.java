package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
import java.util.List;
/* loaded from: classes.dex */
public class SetResourceParentsRequest implements SafeParcelable {
    public static final Parcelable.Creator<SetResourceParentsRequest> CREATOR = new zzbp();
    final int zzCY;
    final DriveId zzagv;
    final List<DriveId> zzagw;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SetResourceParentsRequest(int versionCode, DriveId targetId, List<DriveId> parentIds) {
        this.zzCY = versionCode;
        this.zzagv = targetId;
        this.zzagw = parentIds;
    }

    public SetResourceParentsRequest(DriveId targetId, List<DriveId> parentIds) {
        this(1, targetId, parentIds);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbp.zza(this, dest, flags);
    }
}
