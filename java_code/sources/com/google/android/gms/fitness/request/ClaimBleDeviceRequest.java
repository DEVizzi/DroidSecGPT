package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.data.BleDevice;
import com.google.android.gms.internal.zzmu;
/* loaded from: classes.dex */
public class ClaimBleDeviceRequest implements SafeParcelable {
    public static final Parcelable.Creator<ClaimBleDeviceRequest> CREATOR = new zzb();
    private final int zzCY;
    private final String zzMZ;
    private final String zzalL;
    private final BleDevice zzalM;
    private final zzmu zzalN;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClaimBleDeviceRequest(int versionCode, String deviceAddress, BleDevice bleDevice, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzalL = deviceAddress;
        this.zzalM = bleDevice;
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
    }

    public ClaimBleDeviceRequest(String deviceAddress, BleDevice bleDevice, zzmu callback, String packageName) {
        this.zzCY = 3;
        this.zzalL = deviceAddress;
        this.zzalM = bleDevice;
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
        return String.format("ClaimBleDeviceRequest{%s %s}", this.zzalL, this.zzalM);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzb.zza(this, parcel, flags);
    }

    public BleDevice zzqT() {
        return this.zzalM;
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }
}
