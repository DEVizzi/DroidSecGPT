package com.google.android.gms.maps.model;

import android.os.Parcel;
import android.support.v4.view.ViewCompat;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
/* loaded from: classes.dex */
public final class PolylineOptions implements SafeParcelable {
    public static final zzh CREATOR = new zzh();
    private int mColor;
    private final int zzCY;
    private final List<LatLng> zzaDA;
    private boolean zzaDC;
    private float zzaDa;
    private boolean zzaDb;
    private float zzaDf;

    public PolylineOptions() {
        this.zzaDf = 10.0f;
        this.mColor = ViewCompat.MEASURED_STATE_MASK;
        this.zzaDa = 0.0f;
        this.zzaDb = true;
        this.zzaDC = false;
        this.zzCY = 1;
        this.zzaDA = new ArrayList();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PolylineOptions(int versionCode, List points, float width, int color, float zIndex, boolean visible, boolean geodesic) {
        this.zzaDf = 10.0f;
        this.mColor = ViewCompat.MEASURED_STATE_MASK;
        this.zzaDa = 0.0f;
        this.zzaDb = true;
        this.zzaDC = false;
        this.zzCY = versionCode;
        this.zzaDA = points;
        this.zzaDf = width;
        this.mColor = color;
        this.zzaDa = zIndex;
        this.zzaDb = visible;
        this.zzaDC = geodesic;
    }

    public PolylineOptions add(LatLng point) {
        this.zzaDA.add(point);
        return this;
    }

    public PolylineOptions add(LatLng... points) {
        this.zzaDA.addAll(Arrays.asList(points));
        return this;
    }

    public PolylineOptions addAll(Iterable<LatLng> points) {
        for (LatLng latLng : points) {
            this.zzaDA.add(latLng);
        }
        return this;
    }

    public PolylineOptions color(int color) {
        this.mColor = color;
        return this;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public PolylineOptions geodesic(boolean geodesic) {
        this.zzaDC = geodesic;
        return this;
    }

    public int getColor() {
        return this.mColor;
    }

    public List<LatLng> getPoints() {
        return this.zzaDA;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public float getWidth() {
        return this.zzaDf;
    }

    public float getZIndex() {
        return this.zzaDa;
    }

    public boolean isGeodesic() {
        return this.zzaDC;
    }

    public boolean isVisible() {
        return this.zzaDb;
    }

    public PolylineOptions visible(boolean visible) {
        this.zzaDb = visible;
        return this;
    }

    public PolylineOptions width(float width) {
        this.zzaDf = width;
        return this;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzh.zza(this, out, flags);
    }

    public PolylineOptions zIndex(float zIndex) {
        this.zzaDa = zIndex;
        return this;
    }
}
