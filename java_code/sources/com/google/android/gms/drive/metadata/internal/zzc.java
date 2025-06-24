package com.google.android.gms.drive.metadata.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.drive.metadata.CustomPropertyKey;
/* loaded from: classes.dex */
public class zzc implements Parcelable.Creator<CustomProperty> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(CustomProperty customProperty, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, customProperty.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) customProperty.zzagG, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, customProperty.mValue, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzbB */
    public CustomProperty createFromParcel(Parcel parcel) {
        String zzo;
        CustomPropertyKey customPropertyKey;
        int i;
        String str = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        CustomPropertyKey customPropertyKey2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    String str2 = str;
                    customPropertyKey = customPropertyKey2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzo = str2;
                    break;
                case 2:
                    CustomPropertyKey customPropertyKey3 = (CustomPropertyKey) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, CustomPropertyKey.CREATOR);
                    i = i2;
                    zzo = str;
                    customPropertyKey = customPropertyKey3;
                    break;
                case 3:
                    zzo = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    customPropertyKey = customPropertyKey2;
                    i = i2;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzo = str;
                    customPropertyKey = customPropertyKey2;
                    i = i2;
                    break;
            }
            i2 = i;
            customPropertyKey2 = customPropertyKey;
            str = zzo;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new CustomProperty(i2, customPropertyKey2, str);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzdq */
    public CustomProperty[] newArray(int i) {
        return new CustomProperty[i];
    }
}
