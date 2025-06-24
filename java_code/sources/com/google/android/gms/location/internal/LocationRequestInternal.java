package com.google.android.gms.location.internal;

import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.common.internal.zzt;
import com.google.android.gms.location.LocationRequest;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class LocationRequestInternal implements SafeParcelable {
    final String mTag;
    private final int zzCY;
    LocationRequest zzamz;
    boolean zzazb;
    boolean zzazc;
    boolean zzazd;
    List<ClientIdentity> zzaze;
    static final List<ClientIdentity> zzaza = Collections.emptyList();
    public static final zzk CREATOR = new zzk();

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocationRequestInternal(int versionCode, LocationRequest locationRequest, boolean requestNlpDebugInfo, boolean restorePendingIntentListeners, boolean triggerUpdate, List<ClientIdentity> clients, String tag) {
        this.zzCY = versionCode;
        this.zzamz = locationRequest;
        this.zzazb = requestNlpDebugInfo;
        this.zzazc = restorePendingIntentListeners;
        this.zzazd = triggerUpdate;
        this.zzaze = clients;
        this.mTag = tag;
    }

    public static LocationRequestInternal zza(String str, LocationRequest locationRequest) {
        return new LocationRequestInternal(1, locationRequest, false, true, true, zzaza, str);
    }

    public static LocationRequestInternal zzb(LocationRequest locationRequest) {
        return zza(null, locationRequest);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public boolean equals(Object other) {
        if (other instanceof LocationRequestInternal) {
            LocationRequestInternal locationRequestInternal = (LocationRequestInternal) other;
            return zzt.equal(this.zzamz, locationRequestInternal.zzamz) && this.zzazb == locationRequestInternal.zzazb && this.zzazc == locationRequestInternal.zzazc && this.zzazd == locationRequestInternal.zzazd && zzt.equal(this.zzaze, locationRequestInternal.zzaze);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    public int hashCode() {
        return this.zzamz.hashCode();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.zzamz.toString());
        sb.append(" requestNlpDebugInfo=");
        sb.append(this.zzazb);
        sb.append(" restorePendingIntentListeners=");
        sb.append(this.zzazc);
        sb.append(" triggerUpdate=");
        sb.append(this.zzazd);
        sb.append(" clients=");
        sb.append(this.zzaze);
        if (this.mTag != null) {
            sb.append(" tag=");
            sb.append(this.mTag);
        }
        return sb.toString();
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzk.zza(this, parcel, flags);
    }
}
