package com.google.android.gms.location;

import android.content.Intent;
import android.location.Location;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
/* loaded from: classes.dex */
public final class LocationResult implements SafeParcelable {
    private final int zzCY;
    private final List<Location> zzaya;
    static final List<Location> zzaxZ = Collections.emptyList();
    public static final Parcelable.Creator<LocationResult> CREATOR = new zzf();

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocationResult(int versionCode, List<Location> locations) {
        this.zzCY = versionCode;
        this.zzaya = locations;
    }

    public static LocationResult create(List<Location> locations) {
        if (locations == null) {
            locations = zzaxZ;
        }
        return new LocationResult(2, locations);
    }

    public static LocationResult extractResult(Intent intent) {
        if (hasResult(intent)) {
            return (LocationResult) intent.getExtras().getParcelable("com.google.android.gms.location.EXTRA_LOCATION_RESULT");
        }
        return null;
    }

    public static boolean hasResult(Intent intent) {
        if (intent == null) {
            return false;
        }
        return intent.hasExtra("com.google.android.gms.location.EXTRA_LOCATION_RESULT");
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object other) {
        if (other instanceof LocationResult) {
            LocationResult locationResult = (LocationResult) other;
            if (locationResult.zzaya.size() != this.zzaya.size()) {
                return false;
            }
            Iterator<Location> it = locationResult.zzaya.iterator();
            Iterator<Location> it2 = this.zzaya.iterator();
            while (it.hasNext()) {
                if (it2.next().getTime() != it.next().getTime()) {
                    return false;
                }
            }
            return true;
        }
        return false;
    }

    public Location getLastLocation() {
        int size = this.zzaya.size();
        if (size == 0) {
            return null;
        }
        return this.zzaya.get(size - 1);
    }

    public List<Location> getLocations() {
        return this.zzaya;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        int i = 17;
        Iterator<Location> it = this.zzaya.iterator();
        while (true) {
            int i2 = i;
            if (!it.hasNext()) {
                return i2;
            }
            long time = it.next().getTime();
            i = ((int) (time ^ (time >>> 32))) + (i2 * 31);
        }
    }

    public String toString() {
        return "LocationResult[locations: " + this.zzaya + "]";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzf.zza(this, parcel, flags);
    }
}
