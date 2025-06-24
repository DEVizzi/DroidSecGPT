package com.google.android.gms.drive.realtime.internal.event;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class TextInsertedDetails implements SafeParcelable {
    public static final Parcelable.Creator<TextInsertedDetails> CREATOR = new zzg();
    final int mIndex;
    final int zzCY;
    final int zzaiX;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TextInsertedDetails(int versionCode, int index, int stringDataIndex) {
        this.zzCY = versionCode;
        this.mIndex = index;
        this.zzaiX = stringDataIndex;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzg.zza(this, dest, flags);
    }
}
