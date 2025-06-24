package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.metadata.internal.MetadataBundle;
/* loaded from: classes.dex */
public class OnMetadataResponse implements SafeParcelable {
    public static final Parcelable.Creator<OnMetadataResponse> CREATOR = new zzbd();
    final int zzCY;
    final MetadataBundle zzaeA;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OnMetadataResponse(int versionCode, MetadataBundle metadata) {
        this.zzCY = versionCode;
        this.zzaeA = metadata;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzbd.zza(this, dest, flags);
    }

    public MetadataBundle zzpS() {
        return this.zzaeA;
    }
}
