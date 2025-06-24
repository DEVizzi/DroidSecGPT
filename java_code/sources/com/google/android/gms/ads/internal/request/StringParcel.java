package com.google.android.gms.ads.internal.request;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class StringParcel implements SafeParcelable {
    public static final Parcelable.Creator<StringParcel> CREATOR = new zzm();
    final int zzCY;
    String zzuU;

    /* JADX INFO: Access modifiers changed from: package-private */
    public StringParcel(int versionCode, String content) {
        this.zzCY = versionCode;
        this.zzuU = content;
    }

    public StringParcel(String content) {
        this.zzCY = 1;
        this.zzuU = content;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzm.zza(this, dest, flags);
    }

    public String zzfB() {
        return this.zzuU;
    }
}
