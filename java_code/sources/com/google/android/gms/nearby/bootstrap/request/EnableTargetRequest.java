package com.google.android.gms.nearby.bootstrap.request;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzoj;
import com.google.android.gms.internal.zzok;
import com.google.android.gms.internal.zzol;
/* loaded from: classes.dex */
public class EnableTargetRequest implements SafeParcelable {
    public static final zze CREATOR = new zze();
    private final String description;
    private final String name;
    final int versionCode;
    private final byte zzaFg;
    private final zzoj zzaFi;
    private final zzok zzaFj;
    private final zzol zzaFk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public EnableTargetRequest(int versionCode, String name, String description, byte deviceType, IBinder connectionListener, IBinder dataListener, IBinder callback) {
        this.versionCode = versionCode;
        this.name = zzu.zzcj(name);
        this.description = (String) zzu.zzu(description);
        this.zzaFg = deviceType;
        zzu.zzu(connectionListener);
        this.zzaFi = zzoj.zza.zzcV(connectionListener);
        zzu.zzu(dataListener);
        this.zzaFj = zzok.zza.zzcW(dataListener);
        zzu.zzu(callback);
        this.zzaFk = zzol.zza.zzcX(callback);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zze zzeVar = CREATOR;
        return 0;
    }

    public String getDescription() {
        return this.description;
    }

    public String getName() {
        return this.name;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zze zzeVar = CREATOR;
        zze.zza(this, out, flags);
    }

    public IBinder zzqU() {
        if (this.zzaFk == null) {
            return null;
        }
        return this.zzaFk.asBinder();
    }

    public byte zzwK() {
        return this.zzaFg;
    }

    public IBinder zzwO() {
        if (this.zzaFi == null) {
            return null;
        }
        return this.zzaFi.asBinder();
    }

    public IBinder zzwP() {
        if (this.zzaFj == null) {
            return null;
        }
        return this.zzaFj.asBinder();
    }
}
