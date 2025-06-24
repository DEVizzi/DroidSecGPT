package com.google.android.gms.appdatasearch;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.appdatasearch.GetRecentContextCall;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.zza;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzg implements Parcelable.Creator<GetRecentContextCall.Response> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(GetRecentContextCall.Response response, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, response.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, (Parcelable) response.zzNn, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 2, response.zzNo, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, response.zzNp, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzah */
    public GetRecentContextCall.Response[] newArray(int i) {
        return new GetRecentContextCall.Response[i];
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzw */
    public GetRecentContextCall.Response createFromParcel(Parcel parcel) {
        String[] zzA;
        ArrayList arrayList;
        Status status;
        int i;
        String[] strArr = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        ArrayList arrayList2 = null;
        Status status2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = i2;
                    ArrayList arrayList3 = arrayList2;
                    status = (Status) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Status.CREATOR);
                    zzA = strArr;
                    arrayList = arrayList3;
                    break;
                case 2:
                    status = status2;
                    i = i2;
                    String[] strArr2 = strArr;
                    arrayList = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, UsageInfo.CREATOR);
                    zzA = strArr2;
                    break;
                case 3:
                    zzA = com.google.android.gms.common.internal.safeparcel.zza.zzA(parcel, zzaa);
                    arrayList = arrayList2;
                    status = status2;
                    i = i2;
                    break;
                case 1000:
                    String[] strArr3 = strArr;
                    arrayList = arrayList2;
                    status = status2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzA = strArr3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzA = strArr;
                    arrayList = arrayList2;
                    status = status2;
                    i = i2;
                    break;
            }
            i2 = i;
            status2 = status;
            arrayList2 = arrayList;
            strArr = zzA;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new GetRecentContextCall.Response(i2, status2, arrayList2, strArr);
    }
}
