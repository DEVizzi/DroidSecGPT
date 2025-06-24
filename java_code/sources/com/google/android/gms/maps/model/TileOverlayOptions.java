package com.google.android.gms.maps.model;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.maps.model.internal.zzl;
/* loaded from: classes.dex */
public final class TileOverlayOptions implements SafeParcelable {
    public static final zzn CREATOR = new zzn();
    private final int zzCY;
    private com.google.android.gms.maps.model.internal.zzl zzaDG;
    private TileProvider zzaDH;
    private boolean zzaDI;
    private float zzaDa;
    private boolean zzaDb;

    public TileOverlayOptions() {
        this.zzaDb = true;
        this.zzaDI = true;
        this.zzCY = 1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TileOverlayOptions(int versionCode, IBinder delegate, boolean visible, float zIndex, boolean fadeIn) {
        this.zzaDb = true;
        this.zzaDI = true;
        this.zzCY = versionCode;
        this.zzaDG = zzl.zza.zzcT(delegate);
        this.zzaDH = this.zzaDG == null ? null : new TileProvider() { // from class: com.google.android.gms.maps.model.TileOverlayOptions.1
            private final com.google.android.gms.maps.model.internal.zzl zzaDJ;

            {
                this.zzaDJ = TileOverlayOptions.this.zzaDG;
            }

            @Override // com.google.android.gms.maps.model.TileProvider
            public Tile getTile(int x, int y, int zoom) {
                try {
                    return this.zzaDJ.getTile(x, y, zoom);
                } catch (RemoteException e) {
                    return null;
                }
            }
        };
        this.zzaDb = visible;
        this.zzaDa = zIndex;
        this.zzaDI = fadeIn;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public TileOverlayOptions fadeIn(boolean fadeIn) {
        this.zzaDI = fadeIn;
        return this;
    }

    public boolean getFadeIn() {
        return this.zzaDI;
    }

    public TileProvider getTileProvider() {
        return this.zzaDH;
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

    public TileOverlayOptions tileProvider(final TileProvider tileProvider) {
        this.zzaDH = tileProvider;
        this.zzaDG = this.zzaDH == null ? null : new zzl.zza() { // from class: com.google.android.gms.maps.model.TileOverlayOptions.2
            @Override // com.google.android.gms.maps.model.internal.zzl
            public Tile getTile(int x, int y, int zoom) {
                return tileProvider.getTile(x, y, zoom);
            }
        };
        return this;
    }

    public TileOverlayOptions visible(boolean visible) {
        this.zzaDb = visible;
        return this;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        zzn.zza(this, out, flags);
    }

    public TileOverlayOptions zIndex(float zIndex) {
        this.zzaDa = zIndex;
        return this;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzvL() {
        return this.zzaDG.asBinder();
    }
}
