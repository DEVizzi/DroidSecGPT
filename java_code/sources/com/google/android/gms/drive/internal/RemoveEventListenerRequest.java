package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class RemoveEventListenerRequest implements SafeParcelable {
    public static final Parcelable.Creator<RemoveEventListenerRequest> CREATOR = new zzbl();
    final int zzCY;
    final DriveId zzacT;
    final int zzaca;

    /* JADX INFO: Access modifiers changed from: package-private */
    public RemoveEventListenerRequest(int versionCode, DriveId driveId, int eventType) {
        this.zzCY = versionCode;
        this.zzacT = driveId;
        this.zzaca = eventType;
    }

    public RemoveEventListenerRequest(DriveId id, int eventType) {
        this(1, id, eventType);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbl.zza(this, dest, flags);
    }
}
