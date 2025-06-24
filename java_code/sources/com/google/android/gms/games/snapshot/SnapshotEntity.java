package com.google.android.gms.games.snapshot;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
/* loaded from: classes.dex */
public final class SnapshotEntity implements SafeParcelable, Snapshot {
    public static final Parcelable.Creator<SnapshotEntity> CREATOR = new SnapshotEntityCreator();
    private final int zzCY;
    private final SnapshotMetadataEntity zzavk;
    private final SnapshotContentsEntity zzavl;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SnapshotEntity(int versionCode, SnapshotMetadata metadata, SnapshotContentsEntity contents) {
        this.zzCY = versionCode;
        this.zzavk = new SnapshotMetadataEntity(metadata);
        this.zzavl = contents;
    }

    public SnapshotEntity(SnapshotMetadata metadata, SnapshotContentsEntity contents) {
        this(2, metadata, contents);
    }

    private boolean isClosed() {
        return this.zzavl.isClosed();
    }

    static boolean zza(Snapshot snapshot, Object obj) {
        if (obj instanceof Snapshot) {
            if (snapshot != obj) {
                Snapshot snapshot2 = (Snapshot) obj;
                return zzt.equal(snapshot2.getMetadata(), snapshot.getMetadata()) && zzt.equal(snapshot2.getSnapshotContents(), snapshot.getSnapshotContents());
            }
            return true;
        }
        return false;
    }

    static int zzb(Snapshot snapshot) {
        return zzt.hashCode(snapshot.getMetadata(), snapshot.getSnapshotContents());
    }

    static String zzc(Snapshot snapshot) {
        return zzt.zzt(snapshot).zzg("Metadata", snapshot.getMetadata()).zzg("HasContents", Boolean.valueOf(snapshot.getSnapshotContents() != null)).toString();
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object obj) {
        return zza(this, obj);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.google.android.gms.common.data.Freezable
    public Snapshot freeze() {
        return this;
    }

    @Override // com.google.android.gms.games.snapshot.Snapshot
    public SnapshotMetadata getMetadata() {
        return this.zzavk;
    }

    @Override // com.google.android.gms.games.snapshot.Snapshot
    public SnapshotContents getSnapshotContents() {
        if (isClosed()) {
            return null;
        }
        return this.zzavl;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return zzb(this);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    public String toString() {
        return zzc(this);
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel out, int flags) {
        SnapshotEntityCreator.zza(this, out, flags);
    }
}
