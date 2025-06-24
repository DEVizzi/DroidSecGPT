package com.google.android.gms.fitness.result;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public class SyncInfoResult implements Result, SafeParcelable {
    public static final Parcelable.Creator<SyncInfoResult> CREATOR = new zzl();
    private final int zzCY;
    private final Status zzOt;
    private final long zzVp;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SyncInfoResult(int versionCode, Status status, long timestamp) {
        this.zzCY = versionCode;
        this.zzOt = status;
        this.zzVp = timestamp;
    }

    private boolean zzb(SyncInfoResult syncInfoResult) {
        return this.zzOt.equals(syncInfoResult.zzOt) && zzt.equal(Long.valueOf(this.zzVp), Long.valueOf(syncInfoResult.zzVp));
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object that) {
        return this == that || ((that instanceof SyncInfoResult) && zzb((SyncInfoResult) that));
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzOt, Long.valueOf(this.zzVp));
    }

    public String toString() {
        return zzt.zzt(this).zzg("status", this.zzOt).zzg("timestamp", Long.valueOf(this.zzVp)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzl.zza(this, dest, flags);
    }

    public long zzrz() {
        return this.zzVp;
    }
}
