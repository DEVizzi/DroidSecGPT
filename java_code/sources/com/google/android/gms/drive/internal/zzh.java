package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.drive.Contents;
/* loaded from: classes.dex */
public class zzh implements Parcelable.Creator<CloseContentsRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(CloseContentsRequest closeContentsRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, closeContentsRequest.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) closeContentsRequest.zzaes, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, closeContentsRequest.zzaew, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 4, closeContentsRequest.zzaeu);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzaH */
    public CloseContentsRequest createFromParcel(Parcel parcel) {
        int zzg;
        Boolean bool;
        Contents contents;
        int i;
        Boolean bool2 = null;
        int i2 = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        Contents contents2 = null;
        int i3 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    int i4 = i2;
                    bool = bool2;
                    contents = contents2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzg = i4;
                    break;
                case 2:
                    i = i3;
                    Boolean bool3 = bool2;
                    contents = (Contents) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Contents.CREATOR);
                    zzg = i2;
                    bool = bool3;
                    break;
                case 3:
                    contents = contents2;
                    i = i3;
                    int i5 = i2;
                    bool = com.google.android.gms.common.internal.safeparcel.zza.zzd(parcel, zzaa);
                    zzg = i5;
                    break;
                case 4:
                    zzg = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    bool = bool2;
                    contents = contents2;
                    i = i3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzg = i2;
                    bool = bool2;
                    contents = contents2;
                    i = i3;
                    break;
            }
            i3 = i;
            contents2 = contents;
            bool2 = bool;
            i2 = zzg;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new CloseContentsRequest(i3, contents2, bool2, i2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcr */
    public CloseContentsRequest[] newArray(int i) {
        return new CloseContentsRequest[i];
    }
}
