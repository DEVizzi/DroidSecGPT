package com.google.android.gms.nearby.sharing;

import android.net.Uri;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zza implements Parcelable.Creator<AppContentReceivedResult> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(AppContentReceivedResult appContentReceivedResult, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, appContentReceivedResult.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, (Parcelable) appContentReceivedResult.zzxc(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 3, appContentReceivedResult.getStatusCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfy */
    public AppContentReceivedResult createFromParcel(Parcel parcel) {
        int zzg;
        Uri uri;
        int i;
        int i2 = 0;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        Uri uri2 = null;
        int i3 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    int i4 = i2;
                    uri = uri2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzg = i4;
                    break;
                case 2:
                    Uri uri3 = (Uri) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Uri.CREATOR);
                    i = i3;
                    zzg = i2;
                    uri = uri3;
                    break;
                case 3:
                    zzg = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    uri = uri2;
                    i = i3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzg = i2;
                    uri = uri2;
                    i = i3;
                    break;
            }
            i3 = i;
            uri2 = uri;
            i2 = zzg;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new AppContentReceivedResult(i3, uri2, i2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzin */
    public AppContentReceivedResult[] newArray(int i) {
        return new AppContentReceivedResult[i];
    }
}
