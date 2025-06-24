package com.google.android.gms.location;

import android.content.Intent;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
/* loaded from: classes.dex */
public final class LocationSettingsStates implements SafeParcelable {
    public static final Parcelable.Creator<LocationSettingsStates> CREATOR = new zzi();
    private final int zzCY;
    private final boolean zzayg;
    private final boolean zzayh;
    private final boolean zzayi;
    private final boolean zzayj;
    private final boolean zzayk;
    private final boolean zzayl;
    private final boolean zzaym;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocationSettingsStates(int version, boolean gpsUsable, boolean nlpUsable, boolean bleUsable, boolean gpsPresent, boolean nlpPresent, boolean blePresent, boolean userLocationReportingOn) {
        this.zzCY = version;
        this.zzayg = gpsUsable;
        this.zzayh = nlpUsable;
        this.zzayi = bleUsable;
        this.zzayj = gpsPresent;
        this.zzayk = nlpPresent;
        this.zzayl = blePresent;
        this.zzaym = userLocationReportingOn;
    }

    public static LocationSettingsStates fromIntent(Intent intent) {
        return (LocationSettingsStates) com.google.android.gms.common.internal.safeparcel.zzc.zza(intent, "com.google.android.gms.location.LOCATION_SETTINGS_STATES", CREATOR);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    public int getVersionCode() {
        return this.zzCY;
    }

    public boolean isBlePresent() {
        return this.zzayl;
    }

    public boolean isBleUsable() {
        return this.zzayi;
    }

    public boolean isGpsPresent() {
        return this.zzayj;
    }

    public boolean isGpsUsable() {
        return this.zzayg;
    }

    public boolean isLocationPresent() {
        return this.zzayj || this.zzayk;
    }

    public boolean isLocationUsable() {
        return this.zzayg || this.zzayh;
    }

    public boolean isNetworkLocationPresent() {
        return this.zzayk;
    }

    public boolean isNetworkLocationUsable() {
        return this.zzayh;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zzi.zza(this, dest, flags);
    }

    public boolean zzus() {
        return this.zzaym;
    }
}
