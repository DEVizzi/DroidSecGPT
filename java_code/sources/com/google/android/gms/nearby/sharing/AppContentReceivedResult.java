package com.google.android.gms.nearby.sharing;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public class AppContentReceivedResult implements SafeParcelable {
    public static final Parcelable.Creator<AppContentReceivedResult> CREATOR = new zza();
    private int statusCode;
    private final int versionCode;
    private Uri zzaGj;

    private AppContentReceivedResult() {
        this.versionCode = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public AppContentReceivedResult(int versionCode, Uri destinationUri, int statusCode) {
        this.versionCode = versionCode;
        this.zzaGj = destinationUri;
        this.statusCode = statusCode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof AppContentReceivedResult) {
            AppContentReceivedResult appContentReceivedResult = (AppContentReceivedResult) o;
            return zzt.equal(this.zzaGj, appContentReceivedResult.zzaGj) && zzt.equal(Integer.valueOf(this.statusCode), Integer.valueOf(appContentReceivedResult.statusCode));
        }
        return false;
    }

    public int getStatusCode() {
        return this.statusCode;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.versionCode;
    }

    public int hashCode() {
        return zzt.hashCode(this.zzaGj, Integer.valueOf(this.statusCode));
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zza.zza(this, dest, flags);
    }

    public Uri zzxc() {
        return this.zzaGj;
    }
}
