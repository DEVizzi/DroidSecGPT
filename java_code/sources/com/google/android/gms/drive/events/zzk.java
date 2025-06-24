package com.google.android.gms.drive.events;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzk implements Parcelable.Creator<QueryResultEventParcelable> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(QueryResultEventParcelable queryResultEventParcelable, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, queryResultEventParcelable.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) queryResultEventParcelable.zzWu, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, queryResultEventParcelable.zzaei);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 4, queryResultEventParcelable.zzaej);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzaA */
    public QueryResultEventParcelable createFromParcel(Parcel parcel) {
        int zzg;
        boolean z;
        DataHolder dataHolder;
        int i;
        int i2 = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        DataHolder dataHolder2 = null;
        boolean z2 = false;
        int i3 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    int i4 = i2;
                    z = z2;
                    dataHolder = dataHolder2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzg = i4;
                    break;
                case 2:
                    i = i3;
                    boolean z3 = z2;
                    dataHolder = (DataHolder) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, DataHolder.CREATOR);
                    zzg = i2;
                    z = z3;
                    break;
                case 3:
                    dataHolder = dataHolder2;
                    i = i3;
                    int i5 = i2;
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    zzg = i5;
                    break;
                case 4:
                    zzg = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    z = z2;
                    dataHolder = dataHolder2;
                    i = i3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzg = i2;
                    z = z2;
                    dataHolder = dataHolder2;
                    i = i3;
                    break;
            }
            i3 = i;
            dataHolder2 = dataHolder;
            z2 = z;
            i2 = zzg;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new QueryResultEventParcelable(i3, dataHolder2, z2, i2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcj */
    public QueryResultEventParcelable[] newArray(int i) {
        return new QueryResultEventParcelable[i];
    }
}
