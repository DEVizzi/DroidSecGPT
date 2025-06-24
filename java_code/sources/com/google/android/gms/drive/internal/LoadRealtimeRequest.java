package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
import java.util.List;
/* loaded from: classes.dex */
public class LoadRealtimeRequest implements SafeParcelable {
    public static final Parcelable.Creator<LoadRealtimeRequest> CREATOR = new zzap();
    final int zzCY;
    final DriveId zzacT;
    final boolean zzafQ;
    final List<String> zzafR;
    final boolean zzafS;
    final DataHolder zzafT;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LoadRealtimeRequest(int versionCode, DriveId driveId, boolean useTestMode, List<String> customTypeWhitelist, boolean isInMemory, DataHolder json) {
        this.zzCY = versionCode;
        this.zzacT = driveId;
        this.zzafQ = useTestMode;
        this.zzafR = customTypeWhitelist;
        this.zzafS = isInMemory;
        this.zzafT = json;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzap.zza(this, dest, flags);
    }
}
