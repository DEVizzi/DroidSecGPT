package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzmu;
/* loaded from: classes.dex */
public class UnclaimBleDeviceRequest implements SafeParcelable {
    public static final Parcelable.Creator<UnclaimBleDeviceRequest> CREATOR = new zzad();
    private final int zzCY;
    private final String zzMZ;
    private final String zzalL;
    private final zzmu zzalN;

    /* JADX INFO: Access modifiers changed from: package-private */
    public UnclaimBleDeviceRequest(int versionCode, String deviceAddress, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzalL = deviceAddress;
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
    }

    public UnclaimBleDeviceRequest(String deviceAddress, zzmu callback, String packageName) {
        this.zzCY = 4;
        this.zzalL = deviceAddress;
        this.zzalN = callback;
        this.zzMZ = packageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getDeviceAddress() {
        return this.zzalL;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public String toString() {
        return String.format("UnclaimBleDeviceRequest{%s}", this.zzalL);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzad.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }
}
