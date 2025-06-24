package com.google.android.gms.nearby.sharing.internal;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.nearby.sharing.SharedContent;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzf implements Parcelable.Creator<ProvideContentRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(ProvideContentRequest provideContentRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, provideContentRequest.versionCode);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, provideContentRequest.zzaGp, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, provideContentRequest.zzxi(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 4, provideContentRequest.zzaGr, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, provideContentRequest.zzaGs);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, provideContentRequest.zzxa(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfC */
    public ProvideContentRequest createFromParcel(Parcel parcel) {
        IBinder iBinder = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        long j = 0;
        ArrayList arrayList = null;
        IBinder iBinder2 = null;
        IBinder iBinder3 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    iBinder3 = com.google.android.gms.common.internal.safeparcel.zza.zzp(parcel, zzaa);
                    break;
                case 3:
                    iBinder2 = com.google.android.gms.common.internal.safeparcel.zza.zzp(parcel, zzaa);
                    break;
                case 4:
                    arrayList = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, SharedContent.CREATOR);
                    break;
                case 5:
                    j = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 6:
                    iBinder = com.google.android.gms.common.internal.safeparcel.zza.zzp(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new ProvideContentRequest(i, iBinder3, iBinder2, arrayList, j, iBinder);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzir */
    public ProvideContentRequest[] newArray(int i) {
        return new ProvideContentRequest[i];
    }
}
