package com.google.android.gms.nearby.bootstrap.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.nearby.bootstrap.Device;
/* loaded from: classes.dex */
public class zzf implements Parcelable.Creator<SendDataRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(SendDataRequest sendDataRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, (Parcelable) sendDataRequest.zzwM(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, sendDataRequest.versionCode);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, sendDataRequest.getData(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 3, sendDataRequest.zzqU(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfk */
    public SendDataRequest createFromParcel(Parcel parcel) {
        IBinder zzp;
        byte[] bArr;
        Device device;
        int i;
        IBinder iBinder = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        byte[] bArr2 = null;
        Device device2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    i = i2;
                    byte[] bArr3 = bArr2;
                    device = (Device) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Device.CREATOR);
                    zzp = iBinder;
                    bArr = bArr3;
                    break;
                case 2:
                    device = device2;
                    i = i2;
                    IBinder iBinder2 = iBinder;
                    bArr = com.google.android.gms.common.internal.safeparcel.zza.zzr(parcel, zzaa);
                    zzp = iBinder2;
                    break;
                case 3:
                    zzp = com.google.android.gms.common.internal.safeparcel.zza.zzp(parcel, zzaa);
                    bArr = bArr2;
                    device = device2;
                    i = i2;
                    break;
                case 1000:
                    IBinder iBinder3 = iBinder;
                    bArr = bArr2;
                    device = device2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzp = iBinder3;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzp = iBinder;
                    bArr = bArr2;
                    device = device2;
                    i = i2;
                    break;
            }
            i2 = i;
            device2 = device;
            bArr2 = bArr;
            iBinder = zzp;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new SendDataRequest(i2, device2, bArr2, iBinder);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzhS */
    public SendDataRequest[] newArray(int i) {
        return new SendDataRequest[i];
    }
}
