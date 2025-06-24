package com.google.android.gms.ads.internal.client;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zzp;
import com.google.android.gms.ads.internal.client.zzq;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.dynamic.zzg;
import com.google.android.gms.internal.zzee;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public final class zzd extends com.google.android.gms.dynamic.zzg<zzq> {
    private static final zzd zzrW = new zzd();

    private zzd() {
        super("com.google.android.gms.ads.AdLoaderBuilderCreatorImpl");
    }

    public static zzp zza(Context context, String str, zzee zzeeVar) {
        zzp zzb;
        if (!zzk.zzcA().zzP(context) || (zzb = zzrW.zzb(context, str, zzeeVar)) == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Using AdLoader from the client jar.");
            return new com.google.android.gms.ads.internal.zzi(context, str, zzeeVar, new VersionInfoParcel(7571000, 7571000, true));
        }
        return zzb;
    }

    private zzp zzb(Context context, String str, zzee zzeeVar) {
        try {
            return zzp.zza.zzi(zzak(context).zza(com.google.android.gms.dynamic.zze.zzw(context), str, zzeeVar, 7571000));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not create remote builder for AdLoader.", e);
            return null;
        } catch (zzg.zza e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not create remote builder for AdLoader.", e2);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zzc */
    public zzq zzd(IBinder iBinder) {
        return zzq.zza.zzj(iBinder);
    }
}
