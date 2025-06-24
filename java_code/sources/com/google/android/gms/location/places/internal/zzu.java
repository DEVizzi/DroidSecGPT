package com.google.android.gms.location.places.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.location.places.internal.AutocompletePredictionEntity;
/* loaded from: classes.dex */
public class zzu implements Parcelable.Creator<AutocompletePredictionEntity.SubstringEntity> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(AutocompletePredictionEntity.SubstringEntity substringEntity, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, substringEntity.mOffset);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, substringEntity.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 2, substringEntity.mLength);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzeC */
    public AutocompletePredictionEntity.SubstringEntity createFromParcel(Parcel parcel) {
        int i = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        int i3 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 1000:
                    i3 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new AutocompletePredictionEntity.SubstringEntity(i3, i2, i);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzhc */
    public AutocompletePredictionEntity.SubstringEntity[] newArray(int i) {
        return new AutocompletePredictionEntity.SubstringEntity[i];
    }
}
