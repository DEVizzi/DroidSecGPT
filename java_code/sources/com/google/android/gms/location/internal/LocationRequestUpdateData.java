package com.google.android.gms.location.internal;

import android.app.PendingIntent;
import android.os.IBinder;
import android.os.Parcel;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.location.zzc;
import com.google.android.gms.location.zzd;
/* loaded from: classes.dex */
public class LocationRequestUpdateData implements SafeParcelable {
    public static final zzl CREATOR = new zzl();
    PendingIntent mPendingIntent;
    private final int zzCY;
    int zzazf;
    LocationRequestInternal zzazg;
    com.google.android.gms.location.zzd zzazh;
    com.google.android.gms.location.zzc zzazi;

    /* JADX INFO: Access modifiers changed from: package-private */
    public LocationRequestUpdateData(int versionCode, int operation, LocationRequestInternal locationRequest, IBinder locationListenerBinder, PendingIntent pendingIntent, IBinder locationCallbackBinder) {
        this.zzCY = versionCode;
        this.zzazf = operation;
        this.zzazg = locationRequest;
        this.zzazh = locationListenerBinder == null ? null : zzd.zza.zzbT(locationListenerBinder);
        this.mPendingIntent = pendingIntent;
        this.zzazi = locationCallbackBinder != null ? zzc.zza.zzbS(locationCallbackBinder) : null;
    }

    public static LocationRequestUpdateData zza(LocationRequestInternal locationRequestInternal, com.google.android.gms.location.zzc zzcVar) {
        return new LocationRequestUpdateData(1, 1, locationRequestInternal, null, null, zzcVar.asBinder());
    }

    public static LocationRequestUpdateData zza(com.google.android.gms.location.zzc zzcVar) {
        return new LocationRequestUpdateData(1, 2, null, null, null, zzcVar.asBinder());
    }

    public static LocationRequestUpdateData zzb(LocationRequestInternal locationRequestInternal, PendingIntent pendingIntent) {
        return new LocationRequestUpdateData(1, 1, locationRequestInternal, null, pendingIntent, null);
    }

    public static LocationRequestUpdateData zzb(LocationRequestInternal locationRequestInternal, com.google.android.gms.location.zzd zzdVar) {
        return new LocationRequestUpdateData(1, 1, locationRequestInternal, zzdVar.asBinder(), null, null);
    }

    public static LocationRequestUpdateData zzb(com.google.android.gms.location.zzd zzdVar) {
        return new LocationRequestUpdateData(1, 2, null, zzdVar.asBinder(), null, null);
    }

    public static LocationRequestUpdateData zze(PendingIntent pendingIntent) {
        return new LocationRequestUpdateData(1, 2, null, null, pendingIntent, null);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getVersionCode() {
        return this.zzCY;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel parcel, int flags) {
        zzl.zza(this, parcel, flags);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzuy() {
        if (this.zzazh == null) {
            return null;
        }
        return this.zzazh.asBinder();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public IBinder zzuz() {
        if (this.zzazi == null) {
            return null;
        }
        return this.zzazi.asBinder();
    }
}
