package com.google.android.gms.wallet.wobs;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzg implements Parcelable.Creator<TimeInterval> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(TimeInterval timeInterval, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, timeInterval.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, timeInterval.zzaSH);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, timeInterval.zzaSI);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgE */
    public TimeInterval createFromParcel(Parcel parcel) {
        long j = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        long j2 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    j2 = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 3:
                    j = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new TimeInterval(i, j2, j);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzjJ */
    public TimeInterval[] newArray(int i) {
        return new TimeInterval[i];
    }
}
