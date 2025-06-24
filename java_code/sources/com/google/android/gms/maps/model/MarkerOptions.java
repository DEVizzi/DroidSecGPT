package com.google.android.gms.maps.model;

import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.dynamic.zzd;
/* loaded from: classes.dex */
public final class MarkerOptions implements SafeParcelable {
    public static final zzf CREATOR = new zzf();
    private float mAlpha;
    private final int zzCY;
    private LatLng zzaCx;
    private boolean zzaDb;
    private float zzaDj;
    private float zzaDk;
    private String zzaDs;
    private BitmapDescriptor zzaDt;
    private boolean zzaDu;
    private boolean zzaDv;
    private float zzaDw;
    private float zzaDx;
    private float zzaDy;
    private String zzadv;

    public MarkerOptions() {
        this.zzaDj = 0.5f;
        this.zzaDk = 1.0f;
        this.zzaDb = true;
        this.zzaDv = false;
        this.zzaDw = 0.0f;
        this.zzaDx = 0.5f;
        this.zzaDy = 0.0f;
        this.mAlpha = 1.0f;
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MarkerOptions(int versionCode, LatLng position, String title, String snippet, IBinder wrappedIcon, float anchorU, float anchorV, boolean draggable, boolean visible, boolean flat, float rotation, float infoWindowAnchorU, float infoWindowAnchorV, float alpha) {
        this.zzaDj = 0.5f;
        this.zzaDk = 1.0f;
        this.zzaDb = true;
        this.zzaDv = false;
        this.zzaDw = 0.0f;
        this.zzaDx = 0.5f;
        this.zzaDy = 0.0f;
        this.mAlpha = 1.0f;
        this.zzCY = versionCode;
        this.zzaCx = position;
        this.zzadv = title;
        this.zzaDs = snippet;
        this.zzaDt = wrappedIcon == null ? null : new BitmapDescriptor(zzd.zza.zzbg(wrappedIcon));
        this.zzaDj = anchorU;
        this.zzaDk = anchorV;
        this.zzaDu = draggable;
        this.zzaDb = visible;
        this.zzaDv = flat;
        this.zzaDw = rotation;
        this.zzaDx = infoWindowAnchorU;
        this.zzaDy = infoWindowAnchorV;
        this.mAlpha = alpha;
    }

    public MarkerOptions alpha(float alpha) {
        this.mAlpha = alpha;
        return this;
    }

    public MarkerOptions anchor(float u, float v) {
        this.zzaDj = u;
        this.zzaDk = v;
        return this;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public MarkerOptions draggable(boolean draggable) {
        this.zzaDu = draggable;
        return this;
    }

    public MarkerOptions flat(boolean flat) {
        this.zzaDv = flat;
        return this;
    }

    public float getAlpha() {
        return this.mAlpha;
    }

    public float getAnchorU() {
        return this.zzaDj;
    }

    public float getAnchorV() {
        return this.zzaDk;
    }

    public BitmapDescriptor getIcon() {
        return this.zzaDt;
    }

    public float getInfoWindowAnchorU() {
        return this.zzaDx;
    }

    public float getInfoWindowAnchorV() {
        return this.zzaDy;
    }

    public LatLng getPosition() {
        return this.zzaCx;
    }

    public float getRotation() {
        return this.zzaDw;
    }

    public String getSnippet() {
        return this.zzaDs;
    }

    public String getTitle() {
        return this.zzadv;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public MarkerOptions icon(BitmapDescriptor icon) {
        this.zzaDt = icon;
        return this;
    }

    public MarkerOptions infoWindowAnchor(float u, float v) {
        this.zzaDx = u;
        this.zzaDy = v;
        return this;
    }

    public boolean isDraggable() {
        return this.zzaDu;
    }

    public boolean isFlat() {
        return this.zzaDv;
    }

    public boolean isVisible() {
        return this.zzaDb;
    }

    public MarkerOptions position(LatLng position) {
        this.zzaCx = position;
        return this;
    }

    public MarkerOptions rotation(float rotation) {
        this.zzaDw = rotation;
        return this;
    }

    public MarkerOptions snippet(String snippet) {
        this.zzaDs = snippet;
        return this;
    }

    public MarkerOptions title(String title) {
        this.zzadv = title;
        return this;
    }

    public MarkerOptions visible(boolean visible) {
        this.zzaDb = visible;
        return this;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzf.zza(this, out, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzvJ() {
        if (this.zzaDt == null) {
            return null;
        }
        return this.zzaDt.zzvg().asBinder();
    }
}
