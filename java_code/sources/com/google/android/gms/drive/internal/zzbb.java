package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzbb implements Parcelable.Creator<OnListEntriesResponse> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(OnListEntriesResponse onListEntriesResponse, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, onListEntriesResponse.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) onListEntriesResponse.zzagp, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, onListEntriesResponse.zzaeL);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzbg */
    public OnListEntriesResponse createFromParcel(Parcel parcel) {
        boolean zzc;
        DataHolder dataHolder;
        int i;
        boolean z = false;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        DataHolder dataHolder2 = null;
        int i2 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    boolean z2 = z;
                    dataHolder = dataHolder2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzc = z2;
                    break;
                case 2:
                    DataHolder dataHolder3 = (DataHolder) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, DataHolder.CREATOR);
                    i = i2;
                    zzc = z;
                    dataHolder = dataHolder3;
                    break;
                case 3:
                    zzc = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    dataHolder = dataHolder2;
                    i = i2;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzc = z;
                    dataHolder = dataHolder2;
                    i = i2;
                    break;
            }
            i2 = i;
            dataHolder2 = dataHolder;
            z = zzc;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new OnListEntriesResponse(i2, dataHolder2, z);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcV */
    public OnListEntriesResponse[] newArray(int i) {
        return new OnListEntriesResponse[i];
    }
}
