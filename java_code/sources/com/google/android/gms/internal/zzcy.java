package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.RemoteException;
import android.widget.FrameLayout;
import com.google.android.gms.dynamic.zzg;
import com.google.android.gms.internal.zzcm;
import com.google.android.gms.internal.zzcn;
/* loaded from: classes.dex */
public class zzcy extends com.google.android.gms.dynamic.zzg<zzcn> {
    public zzcy() {
        super("com.google.android.gms.ads.NativeAdViewDelegateCreatorImpl");
    }

    private zzcm zzb(Context context, FrameLayout frameLayout, FrameLayout frameLayout2) {
        try {
            return zzcm.zza.zzu(zzak(context).zza(com.google.android.gms.dynamic.zze.zzw(context), com.google.android.gms.dynamic.zze.zzw(frameLayout), com.google.android.gms.dynamic.zze.zzw(frameLayout2), 7571000));
        } catch (RemoteException | zzg.zza e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not create remote NativeAdViewDelegate.", e);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zzD */
    public zzcn zzd(IBinder iBinder) {
        return zzcn.zza.zzv(iBinder);
    }

    public zzcm zza(Context context, FrameLayout frameLayout, FrameLayout frameLayout2) {
        zzcm zzb;
        if (!com.google.android.gms.ads.internal.client.zzk.zzcA().zzP(context) || (zzb = zzb(context, frameLayout, frameLayout2)) == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Using NativeAdViewDelegate from the client jar.");
            return new com.google.android.gms.ads.internal.formats.zzi(frameLayout, frameLayout2);
        }
        return zzb;
    }
}
