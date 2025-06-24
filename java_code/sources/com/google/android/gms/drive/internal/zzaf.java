package com.google.android.gms.drive.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.drive.ChangeSequenceNumber;
import com.google.android.gms.drive.DriveSpace;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzaf implements Parcelable.Creator<GetChangesRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(GetChangesRequest getChangesRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, getChangesRequest.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) getChangesRequest.zzafJ, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, getChangesRequest.zzafK);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 4, getChangesRequest.zzadR, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzaR */
    public GetChangesRequest createFromParcel(Parcel parcel) {
        ArrayList zzc;
        int i;
        ChangeSequenceNumber changeSequenceNumber;
        int i2;
        ArrayList arrayList = null;
        int i3 = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        ChangeSequenceNumber changeSequenceNumber2 = null;
        int i4 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    ArrayList arrayList2 = arrayList;
                    i = i3;
                    changeSequenceNumber = changeSequenceNumber2;
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzc = arrayList2;
                    break;
                case 2:
                    i2 = i4;
                    int i5 = i3;
                    changeSequenceNumber = (ChangeSequenceNumber) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, ChangeSequenceNumber.CREATOR);
                    zzc = arrayList;
                    i = i5;
                    break;
                case 3:
                    changeSequenceNumber = changeSequenceNumber2;
                    i2 = i4;
                    ArrayList arrayList3 = arrayList;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzc = arrayList3;
                    break;
                case 4:
                    zzc = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, DriveSpace.CREATOR);
                    i = i3;
                    changeSequenceNumber = changeSequenceNumber2;
                    i2 = i4;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzc = arrayList;
                    i = i3;
                    changeSequenceNumber = changeSequenceNumber2;
                    i2 = i4;
                    break;
            }
            i4 = i2;
            changeSequenceNumber2 = changeSequenceNumber;
            i3 = i;
            arrayList = zzc;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new GetChangesRequest(i4, changeSequenceNumber2, i3, arrayList);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzcG */
    public GetChangesRequest[] newArray(int i) {
        return new GetChangesRequest[i];
    }
}
