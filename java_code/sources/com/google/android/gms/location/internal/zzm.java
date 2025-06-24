package com.google.android.gms.location.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzm implements Parcelable.Creator<ParcelableGeofence> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(ParcelableGeofence parcelableGeofence, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, parcelableGeofence.getRequestId(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, parcelableGeofence.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, parcelableGeofence.getExpirationTime());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, parcelableGeofence.zzuA());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, parcelableGeofence.getLatitude());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, parcelableGeofence.getLongitude());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, parcelableGeofence.zzuB());
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 7, parcelableGeofence.zzuC());
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 8, parcelableGeofence.getNotificationResponsiveness());
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 9, parcelableGeofence.zzuD());
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzem */
    public ParcelableGeofence createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str = null;
        int i2 = 0;
        short s = 0;
        double d = 0.0d;
        double d2 = 0.0d;
        float f = 0.0f;
        long j = 0;
        int i3 = 0;
        int i4 = -1;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 2:
                    j = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 3:
                    s = com.google.android.gms.common.internal.safeparcel.zza.zzf(parcel, zzaa);
                    break;
                case 4:
                    d = com.google.android.gms.common.internal.safeparcel.zza.zzm(parcel, zzaa);
                    break;
                case 5:
                    d2 = com.google.android.gms.common.internal.safeparcel.zza.zzm(parcel, zzaa);
                    break;
                case 6:
                    f = com.google.android.gms.common.internal.safeparcel.zza.zzl(parcel, zzaa);
                    break;
                case 7:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 8:
                    i3 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 9:
                    i4 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 1000:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new ParcelableGeofence(i, str, i2, s, d, d2, f, j, i3, i4);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgI */
    public ParcelableGeofence[] newArray(int i) {
        return new ParcelableGeofence[i];
    }
}
