package com.google.android.gms.location.places;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class PlacePhotoMetadataResult implements Result, SafeParcelable {
    public static final Parcelable.Creator<PlacePhotoMetadataResult> CREATOR = new zzi();
    final int zzCY;
    private final Status zzOt;
    final DataHolder zzazH;
    private final zzh zzazI;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PlacePhotoMetadataResult(int versionCode, Status status, DataHolder dataHolder) {
        this.zzCY = versionCode;
        this.zzOt = status;
        this.zzazH = dataHolder;
        if (dataHolder == null) {
            this.zzazI = null;
        } else {
            this.zzazI = new zzh(this.zzazH);
        }
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzOt;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzi.zza(this, parcel, flags);
    }
}
