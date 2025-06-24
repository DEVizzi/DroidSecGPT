package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zzr;
import com.google.android.gms.ads.internal.client.zzs;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamic.zzg;
import com.google.android.gms.internal.zzee;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public class zze extends com.google.android.gms.dynamic.zzg<zzs> {
    public zze() {
        super("com.google.android.gms.ads.AdManagerCreatorImpl");
    }

    private zzr zza(Context context, AdSizeParcel adSizeParcel, String str, zzee zzeeVar, int i) {
        try {
            return zzr.zza.zzk(zzak(context).zza(com.google.android.gms.dynamic.zze.zzw(context), adSizeParcel, str, zzeeVar, 7571000, i));
        } catch (RemoteException | zzg.zza e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not create remote AdManager.", e);
            return null;
        }
    }

    public zzr zza(Context context, AdSizeParcel adSizeParcel, String str, zzee zzeeVar) {
        zzr zza;
        if (!zzk.zzcA().zzP(context) || (zza = zza(context, adSizeParcel, str, zzeeVar, 1)) == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Using BannerAdManager from the client jar.");
            return new com.google.android.gms.ads.internal.zze(context, adSizeParcel, str, zzeeVar, new VersionInfoParcel(7571000, 7571000, true));
        }
        return zza;
    }

    public zzr zzb(Context context, AdSizeParcel adSizeParcel, String str, zzee zzeeVar) {
        zzr zza;
        if (!zzk.zzcA().zzP(context) || (zza = zza(context, adSizeParcel, str, zzeeVar, 2)) == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Using InterstitialAdManager from the client jar.");
            return new com.google.android.gms.ads.internal.zzj(context, adSizeParcel, str, zzeeVar, new VersionInfoParcel(7571000, 7571000, true));
        }
        return zza;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zze */
    public zzs zzd(IBinder iBinder) {
        return zzs.zza.zzl(iBinder);
    }
}
