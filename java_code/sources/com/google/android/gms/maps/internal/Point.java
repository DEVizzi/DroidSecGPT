package com.google.android.gms.maps.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public class Point implements SafeParcelable {
    public static final zzz CREATOR = new zzz();
    private final int versionCode;
    private final android.graphics.Point zzaCO;

    public Point(int versionCode, android.graphics.Point point) {
        this.versionCode = versionCode;
        this.zzaCO = point;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof Point) {
            return this.zzaCO.equals(((Point) o).zzaCO);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.versionCode;
    }

    public int hashCode() {
        return this.zzaCO.hashCode();
    }

    public String toString() {
        return this.zzaCO.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzz.zza(this, out, flags);
    }

    public android.graphics.Point zzvG() {
        return this.zzaCO;
    }
}
