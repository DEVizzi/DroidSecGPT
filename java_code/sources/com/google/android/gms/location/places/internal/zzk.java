package com.google.android.gms.location.places.internal;

import android.net.Uri;
import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.maps.model.LatLng;
import com.google.android.gms.maps.model.LatLngBounds;
import java.util.ArrayList;
/* loaded from: classes.dex */
public class zzk implements Parcelable.Creator<PlaceImpl> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(PlaceImpl placeImpl, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, placeImpl.getId(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, placeImpl.zzuT(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, (Parcelable) placeImpl.zzuV(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 4, (Parcelable) placeImpl.getLatLng(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 5, placeImpl.zzuO());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 6, (Parcelable) placeImpl.getViewport(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 7, placeImpl.zzuU(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 8, (Parcelable) placeImpl.getWebsiteUri(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 9, placeImpl.zzuR());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 10, placeImpl.getRating());
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 11, placeImpl.getPriceLevel());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 12, placeImpl.zzuS());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 13, placeImpl.zzuN(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 14, placeImpl.getAddress(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 15, placeImpl.getPhoneNumber(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzb(parcel, 17, placeImpl.zzuQ(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 16, placeImpl.zzuP(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, placeImpl.zzCY);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 19, placeImpl.getName(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 18, placeImpl.zzaAE);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 20, placeImpl.getPlaceTypes(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzey */
    public PlaceImpl createFromParcel(Parcel parcel) {
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i = 0;
        String str = null;
        ArrayList<Integer> arrayList = null;
        ArrayList<Integer> arrayList2 = null;
        Bundle bundle = null;
        String str2 = null;
        String str3 = null;
        String str4 = null;
        String str5 = null;
        ArrayList<String> arrayList3 = null;
        LatLng latLng = null;
        float f = 0.0f;
        LatLngBounds latLngBounds = null;
        String str6 = null;
        Uri uri = null;
        boolean z = false;
        float f2 = 0.0f;
        int i2 = 0;
        long j = 0;
        boolean z2 = false;
        PlaceLocalization placeLocalization = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 2:
                    bundle = com.google.android.gms.common.internal.safeparcel.zza.zzq(parcel, zzaa);
                    break;
                case 3:
                    placeLocalization = (PlaceLocalization) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, PlaceLocalization.CREATOR);
                    break;
                case 4:
                    latLng = (LatLng) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, LatLng.CREATOR);
                    break;
                case 5:
                    f = com.google.android.gms.common.internal.safeparcel.zza.zzl(parcel, zzaa);
                    break;
                case 6:
                    latLngBounds = (LatLngBounds) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, LatLngBounds.CREATOR);
                    break;
                case 7:
                    str6 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 8:
                    uri = (Uri) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Uri.CREATOR);
                    break;
                case 9:
                    z = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 10:
                    f2 = com.google.android.gms.common.internal.safeparcel.zza.zzl(parcel, zzaa);
                    break;
                case 11:
                    i2 = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    break;
                case 12:
                    j = com.google.android.gms.common.internal.safeparcel.zza.zzi(parcel, zzaa);
                    break;
                case 13:
                    arrayList2 = com.google.android.gms.common.internal.safeparcel.zza.zzB(parcel, zzaa);
                    break;
                case 14:
                    str3 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 15:
                    str4 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 16:
                    str5 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 17:
                    arrayList3 = com.google.android.gms.common.internal.safeparcel.zza.zzC(parcel, zzaa);
                    break;
                case 18:
                    z2 = com.google.android.gms.common.internal.safeparcel.zza.zzc(parcel, zzaa);
                    break;
                case 19:
                    str2 = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    break;
                case 20:
                    arrayList = com.google.android.gms.common.internal.safeparcel.zza.zzB(parcel, zzaa);
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
        return new PlaceImpl(i, str, arrayList, arrayList2, bundle, str2, str3, str4, str5, arrayList3, latLng, f, latLngBounds, str6, uri, z, f2, i2, j, z2, placeLocalization);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzgY */
    public PlaceImpl[] newArray(int i) {
        return new PlaceImpl[i];
    }
}
