package com.google.android.gms.wallet.wobs;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class TimeInterval implements SafeParcelable {
    public static final Parcelable.Creator<TimeInterval> CREATOR = new zzg();
    private final int zzCY;
    long zzaSH;
    long zzaSI;

    TimeInterval() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TimeInterval(int versionCode, long startTimestamp, long endTimestamp) {
        this.zzCY = versionCode;
        this.zzaSH = startTimestamp;
        this.zzaSI = endTimestamp;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }
}
