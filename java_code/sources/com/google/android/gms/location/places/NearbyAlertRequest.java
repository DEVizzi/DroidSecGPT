package com.google.android.gms.location.places;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class NearbyAlertRequest implements SafeParcelable {
    public static final zze CREATOR = new zze();
    private final int zzCY;
    private final int zzaxy;
    private final NearbyAlertFilter zzazA;
    private final int zzazy;
    @Deprecated
    private final PlaceFilter zzazz;

    /* JADX INFO: Access modifiers changed from: package-private */
    public NearbyAlertRequest(int versionCode, int transitionTypes, int loiteringTimeMillis, PlaceFilter placeFilter, NearbyAlertFilter nearbyAlertFilter) {
        this.zzCY = versionCode;
        this.zzaxy = transitionTypes;
        this.zzazy = loiteringTimeMillis;
        if (nearbyAlertFilter != null) {
            this.zzazA = nearbyAlertFilter;
        } else if (placeFilter == null) {
            this.zzazA = null;
        } else if (zza(placeFilter)) {
            this.zzazA = NearbyAlertFilter.zza(placeFilter.getPlaceIds(), placeFilter.getPlaceTypes(), placeFilter.zzuI());
        } else {
            this.zzazA = null;
        }
        this.zzazz = null;
    }

    @Deprecated
    public static boolean zza(PlaceFilter placeFilter) {
        return ((placeFilter.getPlaceTypes() == null || placeFilter.getPlaceTypes().isEmpty()) && (placeFilter.getPlaceIds() == null || placeFilter.getPlaceIds().isEmpty()) && (placeFilter.zzuI() == null || placeFilter.zzuI().isEmpty())) ? false : true;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        zze zzeVar = CREATOR;
        return 0;
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object instanceof NearbyAlertRequest) {
            NearbyAlertRequest nearbyAlertRequest = (NearbyAlertRequest) object;
            return this.zzaxy == nearbyAlertRequest.zzaxy && this.zzazy == nearbyAlertRequest.zzazy && zzt.equal(this.zzazz, nearbyAlertRequest.zzazz) && zzt.equal(this.zzazA, nearbyAlertRequest.zzazA);
        }
        return false;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(Integer.valueOf(this.zzaxy), Integer.valueOf(this.zzazy));
    }

    public String toString() {
        return zzt.zzt(this).zzg("transitionTypes", Integer.valueOf(this.zzaxy)).zzg("loiteringTimeMillis", Integer.valueOf(this.zzazy)).zzg("nearbyAlertFilter", this.zzazA).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zze zzeVar = CREATOR;
        zze.zza(this, parcel, flags);
    }

    public int zzuC() {
        return this.zzaxy;
    }

    public int zzuF() {
        return this.zzazy;
    }

    @Deprecated
    public PlaceFilter zzuG() {
        return this.zzazz;
    }

    public NearbyAlertFilter zzuH() {
        return this.zzazA;
    }
}
