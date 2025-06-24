package com.google.android.gms.location.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public class ClientIdentity implements SafeParcelable {
    public static final zzc CREATOR = new zzc();
    public final String packageName;
    public final int uid;
    private final int zzCY;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ClientIdentity(int versionCode, int uid, String packageName) {
        this.zzCY = versionCode;
        this.uid = uid;
        this.packageName = packageName;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o instanceof ClientIdentity) {
            ClientIdentity clientIdentity = (ClientIdentity) o;
            return clientIdentity.uid == this.uid && zzt.equal(clientIdentity.packageName, this.packageName);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return this.uid;
    }

    public String toString() {
        return String.format("%d:%s", Integer.valueOf(this.uid), this.packageName);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzc.zza(this, parcel, flags);
    }
}
