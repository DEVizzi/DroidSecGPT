package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.Contents;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.ExecutionOptions;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
/* loaded from: classes.dex */
public class CreateFileRequest implements SafeParcelable {
    public static final Parcelable.Creator<CreateFileRequest> CREATOR = new zzl();
    final int zzCY;
    final String zzadn;
    final MetadataBundle zzaeA;
    final Integer zzaeB;
    final DriveId zzaeC;
    final int zzaeD;
    final int zzaeE;
    final boolean zzaen;
    final Contents zzaes;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CreateFileRequest(int versionCode, DriveId parentDriveId, MetadataBundle metadata, Contents contentsReference, Integer fileType, boolean sendEventOnCompletion, String trackingTag, int createStrategy, int openContentsRequestId) {
        if (contentsReference != null && openContentsRequestId != 0) {
            com.google.android.gms.common.internal.zzu.zzb(contentsReference.getRequestId() == openContentsRequestId, "inconsistent contents reference");
        }
        if ((fileType == null || fileType.intValue() == 0) && contentsReference == null && openContentsRequestId == 0) {
            throw new IllegalArgumentException("Need a valid contents");
        }
        this.zzCY = versionCode;
        this.zzaeC = (DriveId) com.google.android.gms.common.internal.zzu.zzu(parentDriveId);
        this.zzaeA = (MetadataBundle) com.google.android.gms.common.internal.zzu.zzu(metadata);
        this.zzaes = contentsReference;
        this.zzaeB = fileType;
        this.zzadn = trackingTag;
        this.zzaeD = createStrategy;
        this.zzaen = sendEventOnCompletion;
        this.zzaeE = openContentsRequestId;
    }

    public CreateFileRequest(DriveId parentDriveId, MetadataBundle metadata, int openContentsRequestId, int fileType, ExecutionOptions executionOptions) {
        this(2, parentDriveId, metadata, null, Integer.valueOf(fileType), executionOptions.zzpj(), executionOptions.zzpi(), executionOptions.zzpk(), openContentsRequestId);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzl.zza(this, dest, flags);
    }
}
