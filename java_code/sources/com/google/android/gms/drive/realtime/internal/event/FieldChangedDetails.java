package com.google.android.gms.drive.realtime.internal.event;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class FieldChangedDetails implements SafeParcelable {
    public static final Parcelable.Creator<FieldChangedDetails> CREATOR = new zza();
    final int zzCY;
    final int zzaiz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FieldChangedDetails(int versionCode, int keyIndex) {
        this.zzCY = versionCode;
        this.zzaiz = keyIndex;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zza.zza(this, dest, flags);
    }
}
