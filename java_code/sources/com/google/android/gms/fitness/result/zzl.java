package com.google.android.gms.fitness.result;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzl implements Parcelable.Creator<SyncInfoResult> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(SyncInfoResult syncInfoResult, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, (Parcelable) syncInfoResult.getStatus(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, syncInfoResult.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, syncInfoResult.zzrz());
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzdp */
    public SyncInfoResult createFromParcel(Parcel parcel) {
        long zzi;
        Status status;
        int i;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        Status status2 = null;
        long j = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    long j2 = j;
                    status = (Status) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Status.CREATOR);
                    i = i2;
                    zzi = j2;
                    break;
                case 2:
                    zzi = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    status = status2;
                    i = i2;
                    break;
                case 1000:
                    long j3 = j;
                    status = status2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzi = j3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzi = j;
                    status = status2;
                    i = i2;
                    break;
            }
            status2 = status;
            i2 = i;
            j = zzi;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new SyncInfoResult(i2, status2, j);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfk */
    public SyncInfoResult[] newArray(int i) {
        return new SyncInfoResult[i];
    }
}
