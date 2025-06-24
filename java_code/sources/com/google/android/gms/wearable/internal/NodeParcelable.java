package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wearable.Node;
/* loaded from: classes.dex */
public class NodeParcelable implements SafeParcelable, Node {
    public static final Parcelable.Creator<NodeParcelable> CREATOR = new zzay();
    final int zzCY;
    private final String zzKI;
    private final int zzaUL;
    private final boolean zzaUM;
    private final String zzadI;

    /* JADX INFO: Access modifiers changed from: package-private */
    public NodeParcelable(int versionCode, String id, String displayName, int hopCount, boolean isNearby) {
        this.zzCY = versionCode;
        this.zzKI = id;
        this.zzadI = displayName;
        this.zzaUL = hopCount;
        this.zzaUM = isNearby;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (o instanceof NodeParcelable) {
            return ((NodeParcelable) o).zzKI.equals(this.zzKI);
        }
        return false;
    }

    @Override // com.google.android.gms.wearable.Node
    public String getDisplayName() {
        return this.zzadI;
    }

    public int getHopCount() {
        return this.zzaUL;
    }

    @Override // com.google.android.gms.wearable.Node
    public String getId() {
        return this.zzKI;
    }

    public int hashCode() {
        return this.zzKI.hashCode();
    }

    @Override // com.google.android.gms.wearable.Node
    public boolean isNearby() {
        return this.zzaUM;
    }

    public String toString() {
        return "Node{" + this.zzadI + ", id=" + this.zzKI + ", hops=" + this.zzaUL + ", isNearby=" + this.zzaUM + "}";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzay.zza(this, dest, flags);
    }
}
