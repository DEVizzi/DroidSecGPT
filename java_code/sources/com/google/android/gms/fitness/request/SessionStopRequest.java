package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.internal.zzmt;
/* loaded from: classes.dex */
public class SessionStopRequest implements SafeParcelable {
    public static final Parcelable.Creator<SessionStopRequest> CREATOR = new zzy();
    private final String mName;
    private final int zzCY;
    private final String zzMZ;
    private final String zzakL;
    private final zzmt zzamJ;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionStopRequest(int versionCode, String name, String identifier, IBinder callback, String packageName) {
        this.zzCY = versionCode;
        this.mName = name;
        this.zzakL = identifier;
        this.zzamJ = callback == null ? null : zzmt.zza.zzbE(callback);
        this.zzMZ = packageName;
    }

    public SessionStopRequest(String name, String identifier, zzmt callback, String packageName) {
        this.zzCY = 2;
        this.mName = name;
        this.zzakL = identifier;
        this.zzamJ = callback;
        this.zzMZ = packageName;
    }

    private boolean zzb(SessionStopRequest sessionStopRequest) {
        return com.google.android.gms.common.internal.zzt.equal(this.mName, sessionStopRequest.mName) && com.google.android.gms.common.internal.zzt.equal(this.zzakL, sessionStopRequest.zzakL);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        return o == this || ((o instanceof SessionStopRequest) && zzb((SessionStopRequest) o));
    }

    public String getIdentifier() {
        return this.zzakL;
    }

    public String getName() {
        return this.mName;
    }

    public String getPackageName() {
        return this.zzMZ;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(this.mName, this.zzakL);
    }

    public String toString() {
        return com.google.android.gms.common.internal.zzt.zzt(this).zzg("name", this.mName).zzg("identifier", this.zzakL).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzy.zza(this, dest, flags);
    }

    public IBinder zzqU() {
        if (this.zzamJ == null) {
            return null;
        }
        return this.zzamJ.asBinder();
    }
}
