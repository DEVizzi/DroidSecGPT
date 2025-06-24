package com.google.android.gms.maps.model.internal;

import android.os.Bundle;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class CameraUpdateParcelable implements SafeParcelable {
    public static final zzb CREATOR = new zzb();
    private int type;
    private final int zzCY;
    private Bundle zzaDN;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CameraUpdateParcelable(int versionCode, int type, Bundle parameters) {
        this.zzCY = versionCode;
        this.type = type;
        this.zzaDN = parameters;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public Bundle getParameters() {
        return this.zzaDN;
    }

    public int getType() {
        return this.type;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }
}
