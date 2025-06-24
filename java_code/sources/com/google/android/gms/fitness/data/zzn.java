package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzn implements Parcelable.Creator<RawDataPoint> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(RawDataPoint rawDataPoint, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, rawDataPoint.zzajV);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, rawDataPoint.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, rawDataPoint.zzajW);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, (Parcelable[]) rawDataPoint.zzajX, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 4, rawDataPoint.zzakH);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 5, rawDataPoint.zzakI);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, rawDataPoint.zzajZ);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, rawDataPoint.zzaka);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzct */
    public RawDataPoint createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        long j = 0;
        long j2 = 0;
        Value[] valueArr = null;
        int i2 = 0;
        int i3 = 0;
        long j3 = 0;
        long j4 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    j = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 2:
                    j2 = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 3:
                    valueArr = (Value[]) com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa, Value.CREATOR);
                    break;
                case 4:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 5:
                    i3 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 6:
                    j3 = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 7:
                    j4 = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 1000:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new RawDataPoint(i, j, j2, valueArr, i2, i3, j3, j4);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzem */
    public RawDataPoint[] newArray(int i) {
        return new RawDataPoint[i];
    }
}
