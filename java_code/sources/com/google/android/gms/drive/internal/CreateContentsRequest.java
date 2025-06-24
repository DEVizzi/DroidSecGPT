package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class CreateContentsRequest implements SafeParcelable {
    public static final Parcelable.Creator<CreateContentsRequest> CREATOR = new zzi();
    final int zzCY;
    final int zzacS;

    public CreateContentsRequest(int mode) {
        this(1, mode);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CreateContentsRequest(int versionCode, int mode) {
        this.zzCY = versionCode;
        com.google.android.gms.common.internal.zzu.zzb(mode == 536870912 || mode == 805306368, "Cannot create a new read-only contents!");
        this.zzacS = mode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzi.zza(this, dest, flags);
    }
}
