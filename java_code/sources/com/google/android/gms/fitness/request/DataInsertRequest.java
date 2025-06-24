package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataSet;
import com.google.android.gms.internal.zzmu;
/* loaded from: classes.dex */
public class DataInsertRequest implements SafeParcelable {
    public static final Parcelable.Creator<DataInsertRequest> CREATOR = new zze();
    private final int zzCY;
    private final String zzMZ;
    private final DataSet zzakO;
    private final zzmu zzalN;
    private final boolean zzalT;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DataInsertRequest(int versionCode, DataSet dataSet, IBinder callback, String packageName, boolean skipSync) {
        this.zzCY = versionCode;
        this.zzakO = dataSet;
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
        this.zzalT = skipSync;
    }

    public DataInsertRequest(DataSet dataSet, zzmu callback, String packageName, boolean skipSync) {
        this.zzCY = 3;
        this.zzakO = dataSet;
        this.zzalN = callback;
        this.zzMZ = packageName;
        this.zzalT = skipSync;
    }

    private boolean zzb(DataInsertRequest dataInsertRequest) {
        return com.google.android.gms.common.internal.zzt.equal(this.zzakO, dataInsertRequest.zzakO);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof DataInsertRequest) && zzb((DataInsertRequest) o));
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.zzakO);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("dataSet", this.zzakO).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zze.zza(this, dest, flags);
    }

    public DataSet zzqK() {
        return this.zzakO;
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }

    public boolean zzqY() {
        return this.zzalT;
    }
}
