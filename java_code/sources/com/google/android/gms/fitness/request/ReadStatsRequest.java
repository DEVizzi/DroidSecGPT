package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzmr;
/* loaded from: classes.dex */
public class ReadStatsRequest implements SafeParcelable {
    public static final Parcelable.Creator<ReadStatsRequest> CREATOR = new zzr();
    private final int zzCY;
    private final String zzMZ;
    private final zzmr zzamq;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReadStatsRequest(int versionCode, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzamq = zzmr.zza.zzbC(callback);
        this.zzMZ = packageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        return String.format("ReadStatsRequest", new Object[0]);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzr.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        return this.zzamq.asBinder();
    }
}
