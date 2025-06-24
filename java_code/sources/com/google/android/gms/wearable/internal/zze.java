package com.google.android.gms.wearable.internal;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zze implements Parcelable.Creator<AncsNotificationParcelable> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(AncsNotificationParcelable ancsNotificationParcelable, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, ancsNotificationParcelable.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 2, ancsNotificationParcelable.getId());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, ancsNotificationParcelable.zzsK(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, ancsNotificationParcelable.zzAU(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, ancsNotificationParcelable.zzAV(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, ancsNotificationParcelable.getTitle(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, ancsNotificationParcelable.zzsb(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 8, ancsNotificationParcelable.getDisplayName(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 9, ancsNotificationParcelable.zzAW());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 10, ancsNotificationParcelable.zzAX());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 11, ancsNotificationParcelable.zzAY());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 12, ancsNotificationParcelable.zzAZ());
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgM */
    public AncsNotificationParcelable createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        int i2 = 0;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        byte b = 0;
        byte b2 = 0;
        byte b3 = 0;
        byte b4 = 0;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 3:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 4:
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 5:
                    str3 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 6:
                    str4 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 7:
                    str5 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 8:
                    str6 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 9:
                    b = com.google.android.gms.common.internal.safeparcel.zza.zze(parcel, zzaa);
                    break;
                case 10:
                    b2 = com.google.android.gms.common.internal.safeparcel.zza.zze(parcel, zzaa);
                    break;
                case 11:
                    b3 = com.google.android.gms.common.internal.safeparcel.zza.zze(parcel, zzaa);
                    break;
                case 12:
                    b4 = com.google.android.gms.common.internal.safeparcel.zza.zze(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new AncsNotificationParcelable(i, i2, str, str2, str3, str4, str5, str6, b, b2, b3, b4);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzjR */
    public AncsNotificationParcelable[] newArray(int i) {
        return new AncsNotificationParcelable[i];
    }
}
