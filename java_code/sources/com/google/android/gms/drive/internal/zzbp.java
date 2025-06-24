package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.drive.DriveId;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzbp implements Parcelable.Creator<SetResourceParentsRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(SetResourceParentsRequest setResourceParentsRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, setResourceParentsRequest.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) setResourceParentsRequest.zzagv, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, setResourceParentsRequest.zzagw, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzbt */
    public SetResourceParentsRequest createFromParcel(Parcel parcel) {
        ArrayList zzc;
        DriveId driveId;
        int i;
        ArrayList arrayList = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        DriveId driveId2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    ArrayList arrayList2 = arrayList;
                    driveId = driveId2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzc = arrayList2;
                    break;
                case 2:
                    DriveId driveId3 = (DriveId) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, DriveId.CREATOR);
                    i = i2;
                    zzc = arrayList;
                    driveId = driveId3;
                    break;
                case 3:
                    zzc = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, DriveId.CREATOR);
                    driveId = driveId2;
                    i = i2;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzc = arrayList;
                    driveId = driveId2;
                    i = i2;
                    break;
            }
            i2 = i;
            driveId2 = driveId;
            arrayList = zzc;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new SetResourceParentsRequest(i2, driveId2, arrayList);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzdi */
    public SetResourceParentsRequest[] newArray(int i) {
        return new SetResourceParentsRequest[i];
    }
}
