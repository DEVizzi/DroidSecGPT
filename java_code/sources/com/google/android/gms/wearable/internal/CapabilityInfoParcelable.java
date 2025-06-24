package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.wearable.CapabilityInfo;
import com.google.android.gms.wearable.Node;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public class CapabilityInfoParcelable implements SafeParcelable, CapabilityInfo {
    public static final Parcelable.Creator<CapabilityInfoParcelable> CREATOR = new zzh();
    private final String mName;
    final int zzCY;
    private final List<NodeParcelable> zzaTH;
    private final Object zzqt = new Object();
    private Set<Node> zzaTE = null;

    /* JADX INFO: Access modifiers changed from: package-private */
    public CapabilityInfoParcelable(int versionCode, String name, List<NodeParcelable> nodeList) {
        this.zzCY = versionCode;
        this.mName = name;
        this.zzaTH = nodeList;
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CapabilityInfoParcelable capabilityInfoParcelable = (CapabilityInfoParcelable) o;
        if (this.zzCY != capabilityInfoParcelable.zzCY) {
            return false;
        }
        if (this.mName == null ? capabilityInfoParcelable.mName != null : !this.mName.equals(capabilityInfoParcelable.mName)) {
            return false;
        }
        if (this.zzaTH != null) {
            if (this.zzaTH.equals(capabilityInfoParcelable.zzaTH)) {
                return true;
            }
        } else if (capabilityInfoParcelable.zzaTH == null) {
            return true;
        }
        return false;
    }

    @Override // com.google.android.gms.wearable.CapabilityInfo
    public String getName() {
        return this.mName;
    }

    @Override // com.google.android.gms.wearable.CapabilityInfo
    public Set<Node> getNodes() {
        Set<Node> set;
        synchronized (this.zzqt) {
            if (this.zzaTE == null) {
                this.zzaTE = new HashSet(this.zzaTH);
            }
            set = this.zzaTE;
        }
        return set;
    }

    public int hashCode() {
        return (((this.mName != null ? this.mName.hashCode() : 0) + (this.zzCY * 31)) * 31) + (this.zzaTH != null ? this.zzaTH.hashCode() : 0);
    }

    public String toString() {
        return "CapabilityInfo{" + this.mName + ", " + this.zzaTH + "}";
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzh.zza(this, dest, flags);
    }

    public List<NodeParcelable> zzBa() {
        return this.zzaTH;
    }
}
