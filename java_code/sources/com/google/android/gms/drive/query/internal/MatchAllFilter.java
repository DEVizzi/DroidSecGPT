package com.google.android.gms.drive.query.internal;

import android.os.Parcel;
/* loaded from: classes.dex */
public class MatchAllFilter extends AbstractFilter {
    public static final zzl CREATOR = new zzl();
    final int zzCY;

    public MatchAllFilter() {
        this(1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MatchAllFilter(int versionCode) {
        this.zzCY = versionCode;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzl.zza(this, out, flags);
    }

    @Override // com.google.android.gms.drive.query.Filter
    public <F> F zza(zzf<F> zzfVar) {
        return zzfVar.zzqf();
    }
}
