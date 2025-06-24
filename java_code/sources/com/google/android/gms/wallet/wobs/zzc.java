package com.google.android.gms.wallet.wobs;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.internal.zzkx;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzc implements Parcelable.Creator<LabelValueRow> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(LabelValueRow labelValueRow, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, labelValueRow.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, labelValueRow.zzaSx, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, labelValueRow.zzaSy, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 4, labelValueRow.zzaSz, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgA */
    public LabelValueRow createFromParcel(Parcel parcel) {
        String str = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        ArrayList zzoP = zzkx.zzoP();
        String str2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 3:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 4:
                    zzoP = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, LabelValue.CREATOR);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new LabelValueRow(i, str2, str, zzoP);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzjF */
    public LabelValueRow[] newArray(int i) {
        return new LabelValueRow[i];
    }
}
