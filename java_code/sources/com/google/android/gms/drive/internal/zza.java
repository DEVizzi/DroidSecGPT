package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.events.ChangesAvailableOptions;
/* loaded from: classes.dex */
public class zza implements Parcelable.Creator<AddEventListenerRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(AddEventListenerRequest addEventListenerRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, addEventListenerRequest.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) addEventListenerRequest.zzacT, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, addEventListenerRequest.zzaca);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, (Parcelable) addEventListenerRequest.zzadO, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzaB */
    public AddEventListenerRequest createFromParcel(Parcel parcel) {
        ChangesAvailableOptions changesAvailableOptions;
        int i;
        DriveId driveId;
        int i2;
        ChangesAvailableOptions changesAvailableOptions2 = null;
        int i3 = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        DriveId driveId2 = null;
        int i4 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    ChangesAvailableOptions changesAvailableOptions3 = changesAvailableOptions2;
                    i = i3;
                    driveId = driveId2;
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    changesAvailableOptions = changesAvailableOptions3;
                    break;
                case 2:
                    i2 = i4;
                    int i5 = i3;
                    driveId = (DriveId) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, DriveId.CREATOR);
                    changesAvailableOptions = changesAvailableOptions2;
                    i = i5;
                    break;
                case 3:
                    driveId = driveId2;
                    i2 = i4;
                    ChangesAvailableOptions changesAvailableOptions4 = changesAvailableOptions2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    changesAvailableOptions = changesAvailableOptions4;
                    break;
                case 4:
                    changesAvailableOptions = (ChangesAvailableOptions) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, ChangesAvailableOptions.CREATOR);
                    i = i3;
                    driveId = driveId2;
                    i2 = i4;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    changesAvailableOptions = changesAvailableOptions2;
                    i = i3;
                    driveId = driveId2;
                    i2 = i4;
                    break;
            }
            i4 = i2;
            driveId2 = driveId;
            i3 = i;
            changesAvailableOptions2 = changesAvailableOptions;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new AddEventListenerRequest(i4, driveId2, i3, changesAvailableOptions2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcl */
    public AddEventListenerRequest[] newArray(int i) {
        return new AddEventListenerRequest[i];
    }
}
