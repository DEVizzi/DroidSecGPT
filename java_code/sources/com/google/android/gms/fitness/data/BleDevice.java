package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzlt;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class BleDevice implements SafeParcelable {
    public static final Parcelable.Creator<BleDevice> CREATOR = new zzb();
    private final String mName;
    private final int zzCY;
    private final String zzajO;
    private final List<String> zzajP;
    private final List<DataType> zzajQ;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BleDevice(int versionCode, String address, String name, List<String> profiles, List<DataType> dataTypes) {
        this.zzCY = versionCode;
        this.zzajO = address;
        this.mName = name;
        this.zzajP = Collections.unmodifiableList(profiles);
        this.zzajQ = Collections.unmodifiableList(dataTypes);
    }

    private boolean zza(BleDevice bleDevice) {
        return this.mName.equals(bleDevice.mName) && this.zzajO.equals(bleDevice.zzajO) && zzlt.zza(bleDevice.zzajP, this.zzajP) && zzlt.zza(this.zzajQ, bleDevice.zzajQ);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof BleDevice) && zza((BleDevice) o));
    }

    public String getAddress() {
        return this.zzajO;
    }

    public List<DataType> getDataTypes() {
        return this.zzajQ;
    }

    public String getName() {
        return this.mName;
    }

    public List<String> getSupportedProfiles() {
        return this.zzajP;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.mName, this.zzajO, this.zzajP, this.zzajQ);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("name", this.mName).zzg("address", this.zzajO).zzg("dataTypes", this.zzajQ).zzg("supportedProfiles", this.zzajP).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzb.zza(this, parcel, flags);
    }
}
