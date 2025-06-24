package com.google.android.gms.nearby.bootstrap.request;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzoj;
import com.google.android.gms.internal.zzok;
import com.google.android.gms.internal.zzol;
import com.google.android.gms.nearby.bootstrap.Device;
/* loaded from: classes.dex */
public class ConnectRequest implements SafeParcelable {
    public static final zza CREATOR = new zza();
    private final String description;
    private final String name;
    final int versionCode;
    private final long zzPr;
    private final byte zzaFg;
    private final Device zzaFh;
    private final zzoj zzaFi;
    private final zzok zzaFj;
    private final zzol zzaFk;
    private final String zzaFl;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ConnectRequest(int versionCode, Device device, String name, String description, byte deviceType, long timeoutMillis, String token, IBinder connectionListener, IBinder dataListener, IBinder callback) {
        this.versionCode = versionCode;
        this.zzaFh = (Device) zzu.zzu(device);
        this.name = zzu.zzcj(name);
        this.description = (String) zzu.zzu(description);
        this.zzaFg = deviceType;
        this.zzPr = timeoutMillis;
        this.zzaFl = token;
        zzu.zzu(connectionListener);
        this.zzaFi = zzoj.zza.zzcV(connectionListener);
        zzu.zzu(dataListener);
        this.zzaFj = zzok.zza.zzcW(dataListener);
        zzu.zzu(callback);
        this.zzaFk = zzol.zza.zzcX(callback);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zza zzaVar = CREATOR;
        return 0;
    }

    public String getDescription() {
        return this.description;
    }

    public String getName() {
        return this.name;
    }

    public String getToken() {
        return this.zzaFl;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zza zzaVar = CREATOR;
        zza.zza(this, out, flags);
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

    public Device zzwM() {
        return this.zzaFh;
    }

    public long zzwN() {
        return this.zzPr;
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
