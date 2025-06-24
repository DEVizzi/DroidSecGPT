package com.google.android.gms.maps.model;

import android.os.Parcel;
import android.support.v4.view.ViewCompat;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class CircleOptions implements SafeParcelable {
    public static final zzb CREATOR = new zzb();
    private final int zzCY;
    private LatLng zzaCV;
    private double zzaCW;
    private float zzaCX;
    private int zzaCY;
    private int zzaCZ;
    private float zzaDa;
    private boolean zzaDb;

    public CircleOptions() {
        this.zzaCV = null;
        this.zzaCW = 0.0d;
        this.zzaCX = 10.0f;
        this.zzaCY = ViewCompat.MEASURED_STATE_MASK;
        this.zzaCZ = 0;
        this.zzaDa = 0.0f;
        this.zzaDb = true;
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CircleOptions(int versionCode, LatLng center, double radius, float strokeWidth, int strokeColor, int fillColor, float zIndex, boolean visible) {
        this.zzaCV = null;
        this.zzaCW = 0.0d;
        this.zzaCX = 10.0f;
        this.zzaCY = ViewCompat.MEASURED_STATE_MASK;
        this.zzaCZ = 0;
        this.zzaDa = 0.0f;
        this.zzaDb = true;
        this.zzCY = versionCode;
        this.zzaCV = center;
        this.zzaCW = radius;
        this.zzaCX = strokeWidth;
        this.zzaCY = strokeColor;
        this.zzaCZ = fillColor;
        this.zzaDa = zIndex;
        this.zzaDb = visible;
    }

    public CircleOptions center(LatLng center) {
        this.zzaCV = center;
        return this;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public CircleOptions fillColor(int color) {
        this.zzaCZ = color;
        return this;
    }

    public LatLng getCenter() {
        return this.zzaCV;
    }

    public int getFillColor() {
        return this.zzaCZ;
    }

    public double getRadius() {
        return this.zzaCW;
    }

    public int getStrokeColor() {
        return this.zzaCY;
    }

    public float getStrokeWidth() {
        return this.zzaCX;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public float getZIndex() {
        return this.zzaDa;
    }

    public boolean isVisible() {
        return this.zzaDb;
    }

    public CircleOptions radius(double radius) {
        this.zzaCW = radius;
        return this;
    }

    public CircleOptions strokeColor(int color) {
        this.zzaCY = color;
        return this;
    }

    public CircleOptions strokeWidth(float width) {
        this.zzaCX = width;
        return this;
    }

    public CircleOptions visible(boolean visible) {
        this.zzaDb = visible;
        return this;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzb.zza(this, out, flags);
    }

    public CircleOptions zIndex(float zIndex) {
        this.zzaDa = zIndex;
        return this;
    }
}
