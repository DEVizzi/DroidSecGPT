package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zzv;
import com.google.android.gms.ads.internal.client.zzw;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamic.zzg;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public class zzac extends com.google.android.gms.dynamic.zzg<zzw> {
    public zzac() {
        super("com.google.android.gms.ads.MobileAdsSettingManagerCreatorImpl");
    }

    private zzv zzu(Context context) {
        try {
            return zzv.zza.zzo(zzak(context).zza(com.google.android.gms.dynamic.zze.zzw(context), 7571000));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get remote MobileAdsSettingManager.", e);
            return null;
        } catch (zzg.zza e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not get remote MobileAdsSettingManager.", e2);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zzq */
    public zzw zzd(IBinder iBinder) {
        return zzw.zza.zzp(iBinder);
    }

    public zzv zzt(Context context) {
        zzv zzu;
        if (!zzk.zzcA().zzP(context) || (zzu = zzu(context)) == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Using MobileAdsSettingManager from the client jar.");
            new VersionInfoParcel(7571000, 7571000, true);
            return com.google.android.gms.ads.internal.zzl.zzq(context);
        }
        return zzu;
    }
}
