package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.fitness.request.zza;
import com.google.android.gms.fitness.request.zzn;
import com.google.android.gms.internal.zzmu;
/* loaded from: classes.dex */
public class StopBleScanRequest implements SafeParcelable {
    public static final Parcelable.Creator<StopBleScanRequest> CREATOR = new zzab();
    private final int zzCY;
    private final String zzMZ;
    private final zzmu zzalN;
    private final zzn zzamK;

    /* JADX INFO: Access modifiers changed from: package-private */
    public StopBleScanRequest(int versionCode, IBinder bleScanCallback, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.zzamK = zzn.zza.zzbI(bleScanCallback);
        this.zzalN = callback == null ? null : zzmu.zza.zzbF(callback);
        this.zzMZ = packageName;
    }

    public StopBleScanRequest(BleScanCallback bleScanCallback, zzmu callback, String packageName) {
        this(zza.C0064zza.zzqS().zzb(bleScanCallback), callback, packageName);
    }

    public StopBleScanRequest(zzn bleScanCallback, zzmu callback, String packageName) {
        this.zzCY = 2;
        this.zzamK = bleScanCallback;
        this.zzalN = callback;
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

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzab.zza(this, parcel, flags);
    }

    public IBinder zzqU() {
        if (this.zzalN == null) {
            return null;
        }
        return this.zzalN.asBinder();
    }

    public IBinder zzrq() {
        return this.zzamK.asBinder();
    }
}
