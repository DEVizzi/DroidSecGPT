package com.google.android.gms.nearby.bootstrap;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public class Device implements SafeParcelable {
    public static final Parcelable.Creator<Device> CREATOR = new zzb();
    private final String description;
    private final String name;
    final int versionCode;
    private final String zzaFf;
    private final byte zzaFg;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Device(int versionCode, String name, String description, String deviceId, byte deviceType) {
        this.versionCode = versionCode;
        this.name = zzu.zzcj(name);
        this.description = (String) zzu.zzu(description);
        this.zzaFf = (String) zzu.zzu(deviceId);
        zzu.zzb(deviceType <= 3, "Unknown device type");
        this.zzaFg = deviceType;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public String getDescription() {
        return this.description;
    }

    public String getDeviceId() {
        return this.zzaFf;
    }

    public String getName() {
        return this.name;
    }

    public String toString() {
        return this.name + ": " + this.description + "[" + ((int) this.zzaFg) + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }

    public byte zzwK() {
        return this.zzaFg;
    }
}
