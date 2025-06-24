package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
/* loaded from: classes.dex */
public class AuthorizeAccessRequest implements SafeParcelable {
    public static final Parcelable.Creator<AuthorizeAccessRequest> CREATOR = new zzc();
    final int zzCY;
    final DriveId zzacT;
    final long zzaeo;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AuthorizeAccessRequest(int versionCode, long appId, DriveId driveId) {
        this.zzCY = versionCode;
        this.zzaeo = appId;
        this.zzacT = driveId;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzc.zza(this, dest, flags);
    }
}
