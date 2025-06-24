package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class OnFetchThumbnailResponse implements SafeParcelable {
    public static final Parcelable.Creator<OnFetchThumbnailResponse> CREATOR = new zzba();
    final int zzCY;
    final ParcelFileDescriptor zzago;

    /* JADX INFO: Access modifiers changed from: package-private */
    public OnFetchThumbnailResponse(int versionCode, ParcelFileDescriptor thumbnailPfd) {
        this.zzCY = versionCode;
        this.zzago = thumbnailPfd;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzba.zza(this, dest, flags | 1);
    }
}
