package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.drive.Contents;
/* loaded from: classes.dex */
public class zzau implements Parcelable.Creator<OnContentsResponse> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(OnContentsResponse onContentsResponse, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, onContentsResponse.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) onContentsResponse.zzafa, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, onContentsResponse.zzage);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzaZ */
    public OnContentsResponse createFromParcel(Parcel parcel) {
        boolean zzc;
        Contents contents;
        int i;
        boolean z = false;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        Contents contents2 = null;
        int i2 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    boolean z2 = z;
                    contents = contents2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzc = z2;
                    break;
                case 2:
                    Contents contents3 = (Contents) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Contents.CREATOR);
                    i = i2;
                    zzc = z;
                    contents = contents3;
                    break;
                case 3:
                    zzc = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    contents = contents2;
                    i = i2;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzc = z;
                    contents = contents2;
                    i = i2;
                    break;
            }
            i2 = i;
            contents2 = contents;
            z = zzc;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new OnContentsResponse(i2, contents2, z);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcO */
    public OnContentsResponse[] newArray(int i) {
        return new OnContentsResponse[i];
    }
}
