package com.google.android.gms.maps.model.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class GroundOverlayOptionsParcelable implements SafeParcelable {
    public static final zzc CREATOR = new zzc();
    private final int zzCY;
    private BitmapDescriptorParcelable zzaDP;

    public GroundOverlayOptionsParcelable() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public GroundOverlayOptionsParcelable(int versionCode, BitmapDescriptorParcelable parcelableImage) {
        this.zzCY = versionCode;
        this.zzaDP = parcelableImage;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzc.zza(this, out, flags);
    }

    public BitmapDescriptorParcelable zzvM() {
        return this.zzaDP;
    }
}
