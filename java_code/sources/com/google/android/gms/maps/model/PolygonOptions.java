package com.google.android.gms.maps.model;

import android.os.Parcel;
import android.support.v4.view.ViewCompat;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
/* loaded from: classes.dex */
public final class PolygonOptions implements SafeParcelable {
    public static final zzg CREATOR = new zzg();
    private final int zzCY;
    private float zzaCX;
    private int zzaCY;
    private int zzaCZ;
    private final List<LatLng> zzaDA;
    private final List<List<LatLng>> zzaDB;
    private boolean zzaDC;
    private float zzaDa;
    private boolean zzaDb;

    public PolygonOptions() {
        this.zzaCX = 10.0f;
        this.zzaCY = ViewCompat.MEASURED_STATE_MASK;
        this.zzaCZ = 0;
        this.zzaDa = 0.0f;
        this.zzaDb = true;
        this.zzaDC = false;
        this.zzCY = 1;
        this.zzaDA = new ArrayList();
        this.zzaDB = new ArrayList();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PolygonOptions(int versionCode, List<LatLng> points, List holes, float strokeWidth, int strokeColor, int fillColor, float zIndex, boolean visible, boolean geodesic) {
        this.zzaCX = 10.0f;
        this.zzaCY = ViewCompat.MEASURED_STATE_MASK;
        this.zzaCZ = 0;
        this.zzaDa = 0.0f;
        this.zzaDb = true;
        this.zzaDC = false;
        this.zzCY = versionCode;
        this.zzaDA = points;
        this.zzaDB = holes;
        this.zzaCX = strokeWidth;
        this.zzaCY = strokeColor;
        this.zzaCZ = fillColor;
        this.zzaDa = zIndex;
        this.zzaDb = visible;
        this.zzaDC = geodesic;
    }

    public PolygonOptions add(LatLng point) {
        this.zzaDA.add(point);
        return this;
    }

    public PolygonOptions add(LatLng... points) {
        this.zzaDA.addAll(Arrays.asList(points));
        return this;
    }

    public PolygonOptions addAll(Iterable<LatLng> points) {
        for (LatLng latLng : points) {
            this.zzaDA.add(latLng);
        }
        return this;
    }

    public PolygonOptions addHole(Iterable<LatLng> points) {
        ArrayList arrayList = new ArrayList();
        for (LatLng latLng : points) {
            arrayList.add(latLng);
        }
        this.zzaDB.add(arrayList);
        return this;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public PolygonOptions fillColor(int color) {
        this.zzaCZ = color;
        return this;
    }

    public PolygonOptions geodesic(boolean geodesic) {
        this.zzaDC = geodesic;
        return this;
    }

    public int getFillColor() {
        return this.zzaCZ;
    }

    public List<List<LatLng>> getHoles() {
        return this.zzaDB;
    }

    public List<LatLng> getPoints() {
        return this.zzaDA;
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

    public boolean isGeodesic() {
        return this.zzaDC;
    }

    public boolean isVisible() {
        return this.zzaDb;
    }

    public PolygonOptions strokeColor(int color) {
        this.zzaCY = color;
        return this;
    }

    public PolygonOptions strokeWidth(float width) {
        this.zzaCX = width;
        return this;
    }

    public PolygonOptions visible(boolean visible) {
        this.zzaDb = visible;
        return this;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzg.zza(this, out, flags);
    }

    public PolygonOptions zIndex(float zIndex) {
        this.zzaDa = zIndex;
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public List zzvK() {
        return this.zzaDB;
    }
}
