package com.google.android.gms.wallet;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public class zzl implements Parcelable.Creator<MaskedWalletRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(MaskedWalletRequest maskedWalletRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, maskedWalletRequest.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, maskedWalletRequest.zzaQn, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, maskedWalletRequest.zzaRi);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, maskedWalletRequest.zzaRj);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, maskedWalletRequest.zzaRk);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, maskedWalletRequest.zzaRl, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, maskedWalletRequest.zzaQg, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 8, maskedWalletRequest.zzaRm, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 9, (Parcelable) maskedWalletRequest.zzaQx, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 10, maskedWalletRequest.zzaRn);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 11, maskedWalletRequest.zzaRo);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 12, (Parcelable[]) maskedWalletRequest.zzaRp, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 13, maskedWalletRequest.zzaRq);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 14, maskedWalletRequest.zzaRr);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 15, maskedWalletRequest.zzaRs, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 17, (List<Integer>) maskedWalletRequest.zzaRu, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 16, (Parcelable) maskedWalletRequest.zzaRt, i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgl */
    public MaskedWalletRequest createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str = null;
        boolean z = false;
        boolean z2 = false;
        boolean z3 = false;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        Cart cart = null;
        boolean z4 = false;
        boolean z5 = false;
        CountrySpecification[] countrySpecificationArr = null;
        boolean z6 = true;
        boolean z7 = true;
        ArrayList arrayList = null;
        PaymentMethodTokenizationParameters paymentMethodTokenizationParameters = null;
        ArrayList<Integer> arrayList2 = null;
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
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 4:
                    z2 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 5:
                    z3 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 6:
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 7:
                    str3 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 8:
                    str4 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 9:
                    cart = (Cart) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Cart.CREATOR);
                    break;
                case 10:
                    z4 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 11:
                    z5 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 12:
                    countrySpecificationArr = (CountrySpecification[]) com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa, CountrySpecification.CREATOR);
                    break;
                case 13:
                    z6 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 14:
                    z7 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 15:
                    arrayList = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa, com.google.android.gms.identity.intents.model.CountrySpecification.CREATOR);
                    break;
                case 16:
                    paymentMethodTokenizationParameters = (PaymentMethodTokenizationParameters) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, PaymentMethodTokenizationParameters.CREATOR);
                    break;
                case 17:
                    arrayList2 = com.google.android.gms.common.internal.safeparcel.zza.zzB(parcel, zzaa);
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    break;
            }
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new MaskedWalletRequest(i, str, z, z2, z3, str2, str3, str4, cart, z4, z5, countrySpecificationArr, z6, z7, arrayList, paymentMethodTokenizationParameters, arrayList2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzjn */
    public MaskedWalletRequest[] newArray(int i) {
        return new MaskedWalletRequest[i];
    }
}
