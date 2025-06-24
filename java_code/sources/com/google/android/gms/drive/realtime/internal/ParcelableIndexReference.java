package com.google.android.gms.drive.realtime.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class ParcelableIndexReference implements SafeParcelable {
    public static final Parcelable.Creator<ParcelableIndexReference> CREATOR = new zzq();
    final int mIndex;
    final int zzCY;
    final String zzaiw;
    final boolean zzaix;
    final int zzaiy;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ParcelableIndexReference(int versionCode, String objectId, int index, boolean legacyCanBeDeleted, int deleteMode) {
        this.zzCY = versionCode;
        this.zzaiw = objectId;
        this.mIndex = index;
        this.zzaix = legacyCanBeDeleted;
        this.zzaiy = deleteMode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzq.zza(this, dest, flags);
    }
}
