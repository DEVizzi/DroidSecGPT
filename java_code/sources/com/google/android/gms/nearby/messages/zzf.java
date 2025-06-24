package com.google.android.gms.nearby.messages;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzf implements Parcelable.Creator<Strategy> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(Strategy strategy, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, strategy.zzaFT);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, strategy.versionCode);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 2, strategy.zzaFU);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, strategy.zzaFV);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, strategy.zzaFW);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 5, strategy.zzaFX);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 6, strategy.zzaFY);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfr */
    public Strategy createFromParcel(Parcel parcel) {
        int i = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        boolean z = false;
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i5 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    i4 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 3:
                    i3 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 4:
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 5:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 6:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 1000:
                    i6 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new Strategy(i6, i5, i4, i3, z, i2, i);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzig */
    public Strategy[] newArray(int i) {
        return new Strategy[i];
    }
}
