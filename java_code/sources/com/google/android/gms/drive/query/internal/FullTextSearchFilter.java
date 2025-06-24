package com.google.android.gms.drive.query.internal;

import android.os.Parcel;
/* loaded from: classes.dex */
public class FullTextSearchFilter extends AbstractFilter {
    public static final zzh CREATOR = new zzh();
    final String mValue;
    final int zzCY;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FullTextSearchFilter(int versionCode, String value) {
        this.zzCY = versionCode;
        this.mValue = value;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzh.zza(this, out, flags);
    }

    @Override // com.google.android.gms.drive.query.Filter
    public <F> F zza(zzf<F> zzfVar) {
        return zzfVar.zzcC(this.mValue);
    }
}
