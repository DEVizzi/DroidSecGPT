package com.google.android.gms.games.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class ConnectionInfo implements SafeParcelable {
    public static final ConnectionInfoCreator CREATOR = new ConnectionInfoCreator();
    private final int zzCY;
    private final String zzaoO;
    private final int zzaoP;

    public ConnectionInfo(int versionCode, String clientAddress, int registrationLatency) {
        this.zzCY = versionCode;
        this.zzaoO = clientAddress;
        this.zzaoP = registrationLatency;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        ConnectionInfoCreator.zza(this, out, flags);
    }

    public String zzsr() {
        return this.zzaoO;
    }

    public int zzss() {
        return this.zzaoP;
    }
}
