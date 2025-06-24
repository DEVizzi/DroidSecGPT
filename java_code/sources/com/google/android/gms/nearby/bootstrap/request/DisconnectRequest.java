package com.google.android.gms.nearby.bootstrap.request;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzol;
import com.google.android.gms.nearby.bootstrap.Device;
/* loaded from: classes.dex */
public class DisconnectRequest implements SafeParcelable {
    public static final zzd CREATOR = new zzd();
    final int versionCode;
    private final Device zzaFh;
    private final zzol zzaFk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DisconnectRequest(int versionCode, Device device, IBinder callback) {
        this.versionCode = versionCode;
        this.zzaFh = (Device) zzu.zzu(device);
        zzu.zzu(callback);
        this.zzaFk = zzol.zza.zzcX(callback);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zzd zzdVar = CREATOR;
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzd zzdVar = CREATOR;
        zzd.zza(this, out, flags);
    }

    public IBinder zzqU() {
        return this.zzaFk.asBinder();
    }

    public Device zzwM() {
        return this.zzaFh;
    }
}
