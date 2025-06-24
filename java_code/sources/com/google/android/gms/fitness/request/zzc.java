package com.google.android.gms.fitness.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.fitness.data.DataType;
/* loaded from: classes.dex */
public class zzc implements Parcelable.Creator<DailyTotalRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(DailyTotalRequest dailyTotalRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, dailyTotalRequest.zzqU(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, dailyTotalRequest.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) dailyTotalRequest.getDataType(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, dailyTotalRequest.getPackageName(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcC */
    public DailyTotalRequest createFromParcel(Parcel parcel) {
        String zzo;
        DataType dataType;
        IBinder iBinder;
        int i;
        String str = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        DataType dataType2 = null;
        IBinder iBinder2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = i2;
                    DataType dataType3 = dataType2;
                    iBinder = com.google.android.gms.common.internal.safeparcel.zza.zzp(parcel, zzaa);
                    zzo = str;
                    dataType = dataType3;
                    break;
                case 2:
                    iBinder = iBinder2;
                    i = i2;
                    String str2 = str;
                    dataType = (DataType) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, DataType.CREATOR);
                    zzo = str2;
                    break;
                case 3:
                    zzo = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    dataType = dataType2;
                    iBinder = iBinder2;
                    i = i2;
                    break;
                case 1000:
                    String str3 = str;
                    dataType = dataType2;
                    iBinder = iBinder2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzo = str3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzo = str;
                    dataType = dataType2;
                    iBinder = iBinder2;
                    i = i2;
                    break;
            }
            i2 = i;
            iBinder2 = iBinder;
            dataType2 = dataType;
            str = zzo;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new DailyTotalRequest(i2, iBinder2, dataType2, str);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzew */
    public DailyTotalRequest[] newArray(int i) {
        return new DailyTotalRequest[i];
    }
}
