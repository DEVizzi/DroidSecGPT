package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.internal.zzkx;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.wallet.wobs.LabelValueRow;
import com.google.android.gms.wallet.wobs.LoyaltyPoints;
import com.google.android.gms.wallet.wobs.TextModuleData;
import com.google.android.gms.wallet.wobs.TimeInterval;
import com.google.android.gms.wallet.wobs.UriData;
import com.google.android.gms.wallet.wobs.WalletObjectMessage;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzj implements Parcelable.Creator<LoyaltyWalletObject> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(LoyaltyWalletObject loyaltyWalletObject, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, loyaltyWalletObject.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, loyaltyWalletObject.zzhI, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, loyaltyWalletObject.zzaQM, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, loyaltyWalletObject.zzaQN, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, loyaltyWalletObject.zzaQO, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, loyaltyWalletObject.zzaBb, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, loyaltyWalletObject.zzaQP, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 8, loyaltyWalletObject.zzaQQ, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 9, loyaltyWalletObject.zzaQR, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 10, loyaltyWalletObject.zzaQS, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 11, loyaltyWalletObject.zzaQT, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 12, loyaltyWalletObject.state);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 13, loyaltyWalletObject.zzaQU, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 14, (Parcelable) loyaltyWalletObject.zzaQV, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 15, loyaltyWalletObject.zzaQW, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 17, loyaltyWalletObject.zzaQY, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 16, loyaltyWalletObject.zzaQX, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 19, loyaltyWalletObject.zzaRa);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 18, loyaltyWalletObject.zzaQZ, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 21, loyaltyWalletObject.zzaRc, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 20, loyaltyWalletObject.zzaRb, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 23, (Parcelable) loyaltyWalletObject.zzaRe, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 22, loyaltyWalletObject.zzaRd, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgj */
    public LoyaltyWalletObject createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        String str6 = null;
        String str7 = null;
        String str8 = null;
        String str9 = null;
        String str10 = null;
        int i2 = 0;
        ArrayList zzoP = zzkx.zzoP();
        TimeInterval timeInterval = null;
        ArrayList zzoP2 = zzkx.zzoP();
        String str11 = null;
        String str12 = null;
        ArrayList zzoP3 = zzkx.zzoP();
        boolean z = false;
        ArrayList zzoP4 = zzkx.zzoP();
        ArrayList zzoP5 = zzkx.zzoP();
        ArrayList zzoP6 = zzkx.zzoP();
        LoyaltyPoints loyaltyPoints = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 2:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 3:
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 4:
                    str3 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 5:
                    str4 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 6:
                    str5 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 7:
                    str6 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 8:
                    str7 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 9:
                    str8 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 10:
                    str9 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 11:
                    str10 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 12:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 13:
                    zzoP = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, WalletObjectMessage.CREATOR);
                    break;
                case 14:
                    timeInterval = (TimeInterval) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, TimeInterval.CREATOR);
                    break;
                case 15:
                    zzoP2 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, LatLng.CREATOR);
                    break;
                case 16:
                    str11 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 17:
                    str12 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 18:
                    zzoP3 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, LabelValueRow.CREATOR);
                    break;
                case 19:
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 20:
                    zzoP4 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, UriData.CREATOR);
                    break;
                case 21:
                    zzoP5 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, TextModuleData.CREATOR);
                    break;
                case 22:
                    zzoP6 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, UriData.CREATOR);
                    break;
                case 23:
                    loyaltyPoints = (LoyaltyPoints) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, LoyaltyPoints.CREATOR);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new LoyaltyWalletObject(i, str, str2, str3, str4, str5, str6, str7, str8, str9, str10, i2, zzoP, timeInterval, zzoP2, str11, str12, zzoP3, z, zzoP4, zzoP5, zzoP6, loyaltyPoints);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzjl */
    public LoyaltyWalletObject[] newArray(int i) {
        return new LoyaltyWalletObject[i];
    }
}
