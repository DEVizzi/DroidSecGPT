package com.google.android.gms.maps.model;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.common.internal.zzu;
/* loaded from: classes.dex */
public final class LatLngBounds implements SafeParcelable {
    public static final zzd CREATOR = new zzd();
    public final LatLng northeast;
    public final LatLng southwest;
    private final int zzCY;

    /* loaded from: classes.dex */
    public static final class Builder {
        private double zzaDn = Double.POSITIVE_INFINITY;
        private double zzaDo = Double.NEGATIVE_INFINITY;
        private double zzaDp = Double.NaN;
        private double zzaDq = Double.NaN;

        private boolean zzg(double d) {
            boolean z = false;
            if (this.zzaDp <= this.zzaDq) {
                return this.zzaDp <= d && d <= this.zzaDq;
            }
            if (this.zzaDp <= d || d <= this.zzaDq) {
                z = true;
            }
            return z;
        }

        public LatLngBounds build() {
            zzu.zza(!Double.isNaN(this.zzaDp), "no included points");
            return new LatLngBounds(new LatLng(this.zzaDn, this.zzaDp), new LatLng(this.zzaDo, this.zzaDq));
        }

        public Builder include(LatLng point) {
            this.zzaDn = Math.min(this.zzaDn, point.latitude);
            this.zzaDo = Math.max(this.zzaDo, point.latitude);
            double d = point.longitude;
            if (Double.isNaN(this.zzaDp)) {
                this.zzaDp = d;
                this.zzaDq = d;
            } else if (!zzg(d)) {
                if (LatLngBounds.zzb(this.zzaDp, d) < LatLngBounds.zzc(this.zzaDq, d)) {
                    this.zzaDp = d;
                } else {
                    this.zzaDq = d;
                }
            }
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public LatLngBounds(int versionCode, LatLng southwest, LatLng northeast) {
        zzu.zzb(southwest, "null southwest");
        zzu.zzb(northeast, "null northeast");
        zzu.zzb(northeast.latitude >= southwest.latitude, "southern latitude exceeds northern latitude (%s > %s)", Double.valueOf(southwest.latitude), Double.valueOf(northeast.latitude));
        this.zzCY = versionCode;
        this.southwest = southwest;
        this.northeast = northeast;
    }

    public LatLngBounds(LatLng southwest, LatLng northeast) {
        this(1, southwest, northeast);
    }

    public static Builder builder() {
        return new Builder();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static double zzb(double d, double d2) {
        return ((d - d2) + 360.0d) % 360.0d;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static double zzc(double d, double d2) {
        return ((d2 - d) + 360.0d) % 360.0d;
    }

    private boolean zzf(double d) {
        return this.southwest.latitude <= d && d <= this.northeast.latitude;
    }

    private boolean zzg(double d) {
        boolean z = false;
        if (this.southwest.longitude <= this.northeast.longitude) {
            return this.southwest.longitude <= d && d <= this.northeast.longitude;
        }
        if (this.southwest.longitude <= d || d <= this.northeast.longitude) {
            z = true;
        }
        return z;
    }

    public boolean contains(LatLng point) {
        return zzf(point.latitude) && zzg(point.longitude);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o instanceof LatLngBounds) {
            LatLngBounds latLngBounds = (LatLngBounds) o;
            return this.southwest.equals(latLngBounds.southwest) && this.northeast.equals(latLngBounds.northeast);
        }
        return false;
    }

    public LatLng getCenter() {
        double d = (this.southwest.latitude + this.northeast.latitude) / 2.0d;
        double d2 = this.northeast.longitude;
        double d3 = this.southwest.longitude;
        return new LatLng(d, d3 <= d2 ? (d2 + d3) / 2.0d : ((d2 + 360.0d) + d3) / 2.0d);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzt.hashCode(this.southwest, this.northeast);
    }

    public LatLngBounds including(LatLng point) {
        double d;
        double min = Math.min(this.southwest.latitude, point.latitude);
        double max = Math.max(this.northeast.latitude, point.latitude);
        double d2 = this.northeast.longitude;
        double d3 = this.southwest.longitude;
        double d4 = point.longitude;
        if (zzg(d4)) {
            d4 = d3;
            d = d2;
        } else if (zzb(d3, d4) < zzc(d2, d4)) {
            d = d2;
        } else {
            d = d4;
            d4 = d3;
        }
        return new LatLngBounds(new LatLng(min, d4), new LatLng(max, d));
    }

    public String toString() {
        return zzt.zzt(this).zzg("southwest", this.southwest).zzg("northeast", this.northeast).toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzd.zza(this, out, flags);
    }
}
