package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.internal.zzmp;
/* loaded from: classes.dex */
public class ListSubscriptionsRequest implements SafeParcelable {
    public static final Parcelable.Creator<ListSubscriptionsRequest> CREATOR = new zzp();
    private final int zzCY;
    private final String zzMZ;
    private final DataType zzajF;
    private final zzmp zzamn;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ListSubscriptionsRequest(int versionCode, DataType dataType, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzajF = dataType;
        this.zzamn = callback == null ? null : zzmp.zza.zzbA(callback);
        this.zzMZ = packageName;
    }

    public ListSubscriptionsRequest(DataType dataType, zzmp callback, String packageName) {
        this.zzCY = 2;
        this.zzajF = dataType;
        this.zzamn = callback;
        this.zzMZ = packageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public DataType getDataType() {
        return this.zzajF;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzp.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        if (this.zzamn == null) {
            return null;
        }
        return this.zzamn.asBinder();
    }
}
