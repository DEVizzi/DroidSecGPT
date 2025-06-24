package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
/* loaded from: classes.dex */
public class CreateFolderRequest implements SafeParcelable {
    public static final Parcelable.Creator<CreateFolderRequest> CREATOR = new zzm();
    final int zzCY;
    final MetadataBundle zzaeA;
    final DriveId zzaeC;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CreateFolderRequest(int versionCode, DriveId parentDriveId, MetadataBundle metadata) {
        this.zzCY = versionCode;
        this.zzaeC = (DriveId) com.google.android.gms.common.internal.zzu.zzu(parentDriveId);
        this.zzaeA = (MetadataBundle) com.google.android.gms.common.internal.zzu.zzu(metadata);
    }

    public CreateFolderRequest(DriveId parentDriveId, MetadataBundle metadata) {
        this(1, parentDriveId, metadata);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzm.zza(this, dest, flags);
    }
}
