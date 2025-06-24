package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzni;
/* loaded from: classes.dex */
public class ListClaimedBleDevicesRequest implements SafeParcelable {
    public static final Parcelable.Creator<ListClaimedBleDevicesRequest> CREATOR = new zzo();
    private final int zzCY;
    private final String zzMZ;
    private final zzni zzamm;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ListClaimedBleDevicesRequest(int versionCode, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzamm = zzni.zza.zzbH(callback);
        this.zzMZ = packageName;
    }

    public ListClaimedBleDevicesRequest(zzni callback, String packageName) {
        this.zzCY = 1;
        this.zzamm = callback;
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
        return String.format("ListClaimedBleDevicesRequest", new Object[0]);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzo.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        return this.zzamm.asBinder();
    }
}
