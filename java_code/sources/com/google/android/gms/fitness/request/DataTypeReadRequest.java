package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzmh;
/* loaded from: classes.dex */
public class DataTypeReadRequest implements SafeParcelable {
    public static final Parcelable.Creator<DataTypeReadRequest> CREATOR = new zzj();
    private final String mName;
    private final int zzCY;
    private final String zzMZ;
    private final zzmh zzamk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataTypeReadRequest(int versionCode, String name, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.mName = name;
        this.zzamk = callback == null ? null : zzmh.zza.zzbs(callback);
        this.zzMZ = packageName;
    }

    public DataTypeReadRequest(String name, zzmh callback, String packageName) {
        this.zzCY = 2;
        this.mName = name;
        this.zzamk = callback;
        this.zzMZ = packageName;
    }

    private boolean zzb(DataTypeReadRequest dataTypeReadRequest) {
        return com.google.android.gms.common.internal.zzt.equal(this.mName, dataTypeReadRequest.mName);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof DataTypeReadRequest) && zzb((DataTypeReadRequest) o));
    }

    public String getName() {
        return this.mName;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.mName);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("name", this.mName).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzj.zza(this, dest, flags);
    }

    public IBinder zzqU() {
        return this.zzamk.asBinder();
    }
}
