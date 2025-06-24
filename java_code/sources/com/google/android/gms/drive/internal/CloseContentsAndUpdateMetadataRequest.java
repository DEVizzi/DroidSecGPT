package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.Contents;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.ExecutionOptions;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
/* loaded from: classes.dex */
public class CloseContentsAndUpdateMetadataRequest implements SafeParcelable {
    public static final Parcelable.Creator<CloseContentsAndUpdateMetadataRequest> CREATOR = new zzg();
    final int zzCY;
    final String zzadn;
    final boolean zzado;
    final DriveId zzaeq;
    final MetadataBundle zzaer;
    final Contents zzaes;
    final int zzaet;
    final int zzaeu;
    final boolean zzaev;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CloseContentsAndUpdateMetadataRequest(int versionCode, DriveId id, MetadataBundle metadataChangeSet, Contents contentsReference, boolean notifyOnCompletion, String trackingTag, int commitStrategy, int contentsRequestId, boolean isContentsValidForConflictDetection) {
        this.zzCY = versionCode;
        this.zzaeq = id;
        this.zzaer = metadataChangeSet;
        this.zzaes = contentsReference;
        this.zzado = notifyOnCompletion;
        this.zzadn = trackingTag;
        this.zzaet = commitStrategy;
        this.zzaeu = contentsRequestId;
        this.zzaev = isContentsValidForConflictDetection;
    }

    public CloseContentsAndUpdateMetadataRequest(DriveId id, MetadataBundle metadataChangeSet, int contentsRequestId, boolean isContentsValidForConflictDetection, ExecutionOptions executionOptions) {
        this(1, id, metadataChangeSet, null, executionOptions.zzpj(), executionOptions.zzpi(), executionOptions.zzpk(), contentsRequestId, isContentsValidForConflictDetection);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }
}
