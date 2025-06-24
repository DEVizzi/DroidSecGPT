package com.google.android.gms.drive.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.ICancelToken;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class DriveServiceResponse implements SafeParcelable {
    public static final Parcelable.Creator<DriveServiceResponse> CREATOR = new zzab();
    final int zzCY;
    final IBinder zzafB;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DriveServiceResponse(int versionCode, IBinder cancelToken) {
        this.zzCY = versionCode;
        this.zzafB = cancelToken;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzab.zza(this, dest, flags);
    }

    public ICancelToken zzpF() {
        return ICancelToken.zza.zzaE(this.zzafB);
    }
}
