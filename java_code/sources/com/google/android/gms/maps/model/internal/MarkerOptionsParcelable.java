package com.google.android.gms.maps.model.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class MarkerOptionsParcelable implements SafeParcelable {
    public static final zzm CREATOR = new zzm();
    private final int zzCY;
    private BitmapDescriptorParcelable zzaDQ;

    public MarkerOptionsParcelable() {
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MarkerOptionsParcelable(int versionCode, BitmapDescriptorParcelable parcelableIcon) {
        this.zzCY = versionCode;
        this.zzaDQ = parcelableIcon;
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
        zzm.zza(this, out, flags);
    }

    public BitmapDescriptorParcelable zzvO() {
        return this.zzaDQ;
    }
}
