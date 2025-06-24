package com.google.android.gms.drive.realtime.internal.event;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class ReferenceShiftedDetails implements SafeParcelable {
    public static final Parcelable.Creator<ReferenceShiftedDetails> CREATOR = new zze();
    final int zzCY;
    final String zzaiT;
    final String zzaiU;
    final int zzaiV;
    final int zzaiW;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReferenceShiftedDetails(int versionCode, String oldObjectId, String newObjectId, int oldIndex, int newIndex) {
        this.zzCY = versionCode;
        this.zzaiT = oldObjectId;
        this.zzaiU = newObjectId;
        this.zzaiV = oldIndex;
        this.zzaiW = newIndex;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zze.zza(this, dest, flags);
    }
}
