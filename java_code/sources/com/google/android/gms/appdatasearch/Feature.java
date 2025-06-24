package com.google.android.gms.appdatasearch;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class Feature implements SafeParcelable {
    public static final zze CREATOR = new zze();
    public final int id;
    final int zzCY;
    final Bundle zzNi;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Feature(int versionCode, int id, Bundle parameters) {
        this.zzCY = versionCode;
        this.id = id;
        this.zzNi = parameters;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zze zzeVar = CREATOR;
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zze zzeVar = CREATOR;
        zze.zza(this, dest, flags);
    }
}
