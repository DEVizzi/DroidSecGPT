package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zza implements Parcelable.Creator<Address> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(Address address, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, address.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, address.name, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, address.zzawA, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, address.zzawB, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, address.zzawC, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, address.zzEr, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, address.zzaQd, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 8, address.zzaQe, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 9, address.zzawH, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 10, address.zzawJ, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 11, address.zzawK);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 12, address.zzawL, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzga */
    public Address createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        String str9 = null;
        boolean z = false;
        String str10 = null;
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
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 4:
                    str3 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 5:
                    str4 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 6:
                    str5 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 7:
                    str6 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 8:
                    str7 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 9:
                    str8 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 10:
                    str9 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 11:
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 12:
                    str10 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new Address(i, str, str2, str3, str4, str5, str6, str7, str8, str9, z, str10);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzjc */
    public Address[] newArray(int i) {
        return new Address[i];
    }
}
