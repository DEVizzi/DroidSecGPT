package com.google.android.gms.fitness.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzo implements Parcelable.Creator<RawDataSet> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(RawDataSet rawDataSet, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, rawDataSet.zzakH);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, rawDataSet.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 2, rawDataSet.zzakJ);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, rawDataSet.zzakK, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, rawDataSet.zzajU);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcu */
    public RawDataSet createFromParcel(Parcel parcel) {
        boolean z = false;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        ArrayList arrayList = null;
        int i = 0;
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
                case 3:
                    arrayList = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, RawDataPoint.CREATOR);
                    break;
                case 4:
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
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
        return new RawDataSet(i3, i2, i, arrayList, z);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzen */
    public RawDataSet[] newArray(int i) {
        return new RawDataSet[i];
    }
}
