package com.google.android.gms.drive;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzh implements Parcelable.Creator<Permission> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(Permission permission, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, permission.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, permission.zzpo(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, permission.zzpp());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, permission.zzpq(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, permission.zzpr(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 6, permission.getRole());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, permission.zzps());
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzas */
    public Permission createFromParcel(Parcel parcel) {
        String str = null;
        boolean z = false;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str2 = null;
        int i2 = 0;
        String str3 = null;
        int i3 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i3 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    str3 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 3:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 4:
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 5:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 6:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 7:
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new Permission(i3, str3, i2, str2, str, i, z);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcb */
    public Permission[] newArray(int i) {
        return new Permission[i];
    }
}
