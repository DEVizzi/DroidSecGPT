package com.google.android.gms.nearby.sharing;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
/* loaded from: classes.dex */
public class zzc implements Parcelable.Creator<SharedContent> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(SharedContent sharedContent, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1, sharedContent.getVersionCode());
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, sharedContent.getUri(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 8, (Parcelable[]) sharedContent.zzxe(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 9, (Parcelable[]) sharedContent.zzxf(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfA */
    public SharedContent createFromParcel(Parcel parcel) {
        LocalContent[] localContentArr;
        ViewableItem[] viewableItemArr;
        String str;
        int i;
        LocalContent[] localContentArr2 = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        ViewableItem[] viewableItemArr2 = null;
        String str2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    LocalContent[] localContentArr3 = localContentArr2;
                    viewableItemArr = viewableItemArr2;
                    str = str2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    localContentArr = localContentArr3;
                    break;
                case 2:
                case 4:
                case 5:
                case 6:
                case 7:
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    localContentArr = localContentArr2;
                    viewableItemArr = viewableItemArr2;
                    str = str2;
                    i = i2;
                    break;
                case 3:
                    i = i2;
                    ViewableItem[] viewableItemArr3 = viewableItemArr2;
                    str = com.google.android.gms.common.internal.safeparcel.zza.zzo(parcel, zzaa);
                    localContentArr = localContentArr2;
                    viewableItemArr = viewableItemArr3;
                    break;
                case 8:
                    str = str2;
                    i = i2;
                    LocalContent[] localContentArr4 = localContentArr2;
                    viewableItemArr = (ViewableItem[]) com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa, ViewableItem.CREATOR);
                    localContentArr = localContentArr4;
                    break;
                case 9:
                    localContentArr = (LocalContent[]) com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa, LocalContent.CREATOR);
                    viewableItemArr = viewableItemArr2;
                    str = str2;
                    i = i2;
                    break;
            }
            i2 = i;
            str2 = str;
            viewableItemArr2 = viewableItemArr;
            localContentArr2 = localContentArr;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new SharedContent(i2, str2, viewableItemArr2, localContentArr2);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzip */
    public SharedContent[] newArray(int i) {
        return new SharedContent[i];
    }
}
