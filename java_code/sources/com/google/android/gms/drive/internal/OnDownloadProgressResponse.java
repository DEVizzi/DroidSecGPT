package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class OnDownloadProgressResponse implements SafeParcelable {
    public static final Parcelable.Creator<OnDownloadProgressResponse> CREATOR = new zzaw();
    final int zzCY;
    final long zzagg;
    final long zzagh;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OnDownloadProgressResponse(int versionCode, long bytesLoaded, long bytesExpected) {
        this.zzCY = versionCode;
        this.zzagg = bytesLoaded;
        this.zzagh = bytesExpected;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzaw.zza(this, dest, flags);
    }

    public long zzpM() {
        return this.zzagg;
    }

    public long zzpN() {
        return this.zzagh;
    }
}
