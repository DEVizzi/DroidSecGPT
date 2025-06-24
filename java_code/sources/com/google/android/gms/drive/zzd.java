package com.google.android.gms.drive;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzd implements Parcelable.Creator<DriveId> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(DriveId driveId, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, driveId.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, driveId.zzadd, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, driveId.zzade);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, driveId.zzacO);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 5, driveId.zzadf);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzap */
    public DriveId createFromParcel(Parcel parcel) {
        long j = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str = null;
        int i2 = -1;
        long j2 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 3:
                    j2 = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 4:
                    j = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 5:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new DriveId(i, str, j2, j, i2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzbU */
    public DriveId[] newArray(int i) {
        return new DriveId[i];
    }
}
