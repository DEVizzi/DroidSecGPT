package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class UpdatePermissionRequest implements SafeParcelable {
    public static final Parcelable.Creator<UpdatePermissionRequest> CREATOR = new zzbv();
    final int zzCY;
    final DriveId zzacT;
    final String zzadn;
    final String zzadz;
    final boolean zzaen;
    final int zzagx;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UpdatePermissionRequest(int versionCode, DriveId driveId, String accountIdentifier, int newRole, boolean sendEventOnCompletion, String trackingTag) {
        this.zzCY = versionCode;
        this.zzacT = driveId;
        this.zzadz = accountIdentifier;
        this.zzagx = newRole;
        this.zzaen = sendEventOnCompletion;
        this.zzadn = trackingTag;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbv.zza(this, dest, flags);
    }
}
