package com.google.android.gms.nearby.bootstrap.request;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.common.internal.safeparcel.zza;
import com.google.android.gms.nearby.bootstrap.Device;
/* loaded from: classes.dex */
public class zzd implements Parcelable.Creator<DisconnectRequest> {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static void zza(DisconnectRequest disconnectRequest, Parcel parcel, int i) {
        int zzac = com.google.android.gms.common.internal.safeparcel.zzb.zzac(parcel);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 1, (Parcelable) disconnectRequest.zzwM(), i, false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzc(parcel, 1000, disconnectRequest.versionCode);
        com.google.android.gms.common.internal.safeparcel.zzb.zza(parcel, 2, disconnectRequest.zzqU(), false);
        com.google.android.gms.common.internal.safeparcel.zzb.zzH(parcel, zzac);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzfi */
    public DisconnectRequest createFromParcel(Parcel parcel) {
        IBinder zzp;
        Device device;
        int i;
        IBinder iBinder = null;
        int zzab = com.google.android.gms.common.internal.safeparcel.zza.zzab(parcel);
        int i2 = 0;
        Device device2 = null;
        while (parcel.dataPosition() < zzab) {
            int zzaa = com.google.android.gms.common.internal.safeparcel.zza.zzaa(parcel);
            switch (com.google.android.gms.common.internal.safeparcel.zza.zzbA(zzaa)) {
                case 1:
                    Device device3 = (Device) com.google.android.gms.common.internal.safeparcel.zza.zza(parcel, zzaa, Device.CREATOR);
                    i = i2;
                    zzp = iBinder;
                    device = device3;
                    break;
                case 2:
                    zzp = com.google.android.gms.common.internal.safeparcel.zza.zzp(parcel, zzaa);
                    device = device2;
                    i = i2;
                    break;
                case 1000:
                    IBinder iBinder2 = iBinder;
                    device = device2;
                    i = com.google.android.gms.common.internal.safeparcel.zza.zzg(parcel, zzaa);
                    zzp = iBinder2;
                    break;
                default:
                    com.google.android.gms.common.internal.safeparcel.zza.zzb(parcel, zzaa);
                    zzp = iBinder;
                    device = device2;
                    i = i2;
                    break;
            }
            i2 = i;
            device2 = device;
            iBinder = zzp;
        }
        if (parcel.dataPosition() != zzab) {
            throw new zza.C0036zza("Overread allowed size end=" + zzab, parcel);
        }
        return new DisconnectRequest(i2, device2, iBinder);
    }

    @Override // android.os.Parcelable.Creator
    /* renamed from: zzhQ */
    public DisconnectRequest[] newArray(int i) {
        return new DisconnectRequest[i];
    }
}
