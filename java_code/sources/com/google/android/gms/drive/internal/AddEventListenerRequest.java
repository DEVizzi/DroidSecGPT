package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.SafeParcelable;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.events.ChangesAvailableOptions;
/* loaded from: classes.dex */
public class AddEventListenerRequest implements SafeParcelable {
    public static final Parcelable.Creator<AddEventListenerRequest> CREATOR = new zza();
    final int zzCY;
    final DriveId zzacT;
    final int zzaca;
    final ChangesAvailableOptions zzadO;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AddEventListenerRequest(int versionCode, DriveId driveId, int eventType, ChangesAvailableOptions changesAvailableOptions) {
        this.zzCY = versionCode;
        this.zzacT = driveId;
        this.zzaca = eventType;
        this.zzadO = changesAvailableOptions;
    }

    public AddEventListenerRequest(DriveId id, int eventType, ChangesAvailableOptions changesAvailableOptions) {
        this(1, id, eventType, changesAvailableOptions);
    }

    @Override // android.os.Parcelable
    public int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public void writeToParcel(Parcel dest, int flags) {
        zza.zza(this, dest, flags);
    }
}
