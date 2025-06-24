package com.google.android.gms.maps.model;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public class StreetViewPanoramaLink implements SafeParcelable {
    public static final zzj CREATOR = new zzj();
    public final float bearing;
    public final String panoId;
    private final int zzCY;

    /* JADX INFO: Access modifiers changed from: package-private */
    public StreetViewPanoramaLink(int versionCode, String panoId, float bearing) {
        this.zzCY = versionCode;
        this.panoId = panoId;
        this.bearing = (((double) bearing) <= 0.0d ? (bearing % 360.0f) + 360.0f : bearing) % 360.0f;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof StreetViewPanoramaLink) {
            StreetViewPanoramaLink streetViewPanoramaLink = (StreetViewPanoramaLink) o;
            return this.panoId.equals(streetViewPanoramaLink.panoId) && Float.floatToIntBits(this.bearing) == Float.floatToIntBits(streetViewPanoramaLink.bearing);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(this.panoId, Float.valueOf(this.bearing));
    }

    public String toString() {
        return zzt.zzt(this).zzg("panoId", this.panoId).zzg("bearing", Float.valueOf(this.bearing)).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzj.zza(this, out, flags);
    }
}
