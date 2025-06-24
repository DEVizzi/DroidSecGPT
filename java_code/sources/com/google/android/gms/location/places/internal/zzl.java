package com.google.android.gms.location.places.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzl implements Parcelable.Creator<PlaceLikelihoodEntity> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(PlaceLikelihoodEntity placeLikelihoodEntity, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, (Parcelable) placeLikelihoodEntity.zzaAK, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, placeLikelihoodEntity.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, placeLikelihoodEntity.zzaAL);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzez */
    public PlaceLikelihoodEntity createFromParcel(Parcel parcel) {
        float zzl;
        PlaceImpl placeImpl;
        int i;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        PlaceImpl placeImpl2 = null;
        float f = 0.0f;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    PlaceImpl placeImpl3 = (PlaceImpl) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, PlaceImpl.CREATOR);
                    i = i2;
                    zzl = f;
                    placeImpl = placeImpl3;
                    break;
                case 2:
                    zzl = com.google.android.gms.common.internal.safeparcel.zza.zzl(parcel, zzaa);
                    placeImpl = placeImpl2;
                    i = i2;
                    break;
                case 1000:
                    float f2 = f;
                    placeImpl = placeImpl2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzl = f2;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzl = f;
                    placeImpl = placeImpl2;
                    i = i2;
                    break;
            }
            i2 = i;
            placeImpl2 = placeImpl;
            f = zzl;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new PlaceLikelihoodEntity(i2, placeImpl2, f);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgZ */
    public PlaceLikelihoodEntity[] newArray(int i) {
        return new PlaceLikelihoodEntity[i];
    }
}
