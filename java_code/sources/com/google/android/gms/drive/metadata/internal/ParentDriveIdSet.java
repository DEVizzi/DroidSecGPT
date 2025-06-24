package com.google.android.gms.drive.metadata.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public class ParentDriveIdSet implements SafeParcelable {
    public static final Parcelable.Creator<ParentDriveIdSet> CREATOR = new zzk();
    final int zzCY;
    final List<PartialDriveId> zzagJ;

    public ParentDriveIdSet() {
        this(1, new ArrayList());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ParentDriveIdSet(int versionCode, List<PartialDriveId> partialDriveIds) {
        this.zzCY = versionCode;
        this.zzagJ = partialDriveIds;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzk.zza(this, out, flags);
    }

    public Set<DriveId> zzC(long j) {
        HashSet hashSet = new HashSet();
        for (PartialDriveId partialDriveId : this.zzagJ) {
            hashSet.add(partialDriveId.zzD(j));
        }
        return hashSet;
    }

    public void zza(PartialDriveId partialDriveId) {
        this.zzagJ.add(partialDriveId);
    }
}
