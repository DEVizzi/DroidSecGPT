package com.google.android.gms.drive.query.internal;

import android.os.Parcel;
/* loaded from: classes.dex */
public class OwnedByMeFilter extends AbstractFilter {
    public static final zzo CREATOR = new zzo();
    final int zzCY;

    public OwnedByMeFilter() {
        this(1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public OwnedByMeFilter(int versionCode) {
        this.zzCY = versionCode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzo.zza(this, out, flags);
    }

    @Override // com.google.android.gms.drive.query.Filter
    public <F> F zza(zzf<F> zzfVar) {
        return zzfVar.zzqe();
    }
}
