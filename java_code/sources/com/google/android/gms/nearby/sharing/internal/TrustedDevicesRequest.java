package com.google.android.gms.nearby.sharing.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.nearby.sharing.internal.zzc;
/* loaded from: classes.dex */
public final class TrustedDevicesRequest implements SafeParcelable {
    public static final Parcelable.Creator<TrustedDevicesRequest> CREATOR = new zzk();
    final int versionCode;
    public zzc zzaGt;
    public String zzaGv;
    public byte[] zzaGw;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TrustedDevicesRequest(int versionCode, String deviceIdentifier, byte[] message, IBinder callbackAsBinder) {
        this.versionCode = versionCode;
        this.zzaGv = (String) zzu.zzu(deviceIdentifier);
        this.zzaGw = (byte[]) zzu.zzu(message);
        this.zzaGt = zzc.zza.zzdj(callbackAsBinder);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzk.zza(this, dest, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzxa() {
        return this.zzaGt.asBinder();
    }
}
