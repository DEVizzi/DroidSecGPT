package com.google.android.gms.maps.model;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class Tile implements SafeParcelable {
    public static final zzm CREATOR = new zzm();
    public final byte[] data;
    public final int height;
    public final int width;
    private final int zzCY;

    /* JADX INFO: Access modifiers changed from: package-private */
    public Tile(int versionCode, int width, int height, byte[] data) {
        this.zzCY = versionCode;
        this.width = width;
        this.height = height;
        this.data = data;
    }

    public Tile(int width, int height, byte[] data) {
        this(1, width, height, data);
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
}
