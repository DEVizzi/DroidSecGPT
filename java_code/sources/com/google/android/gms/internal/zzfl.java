package com.google.android.gms.internal;

import android.app.Activity;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import com.google.android.gms.dynamic.zzg;
import com.google.android.gms.internal.zzfg;
import com.google.android.gms.internal.zzfh;
@zzgd
/* loaded from: classes.dex */
public final class zzfl extends com.google.android.gms.dynamic.zzg<zzfh> {
    private static final zzfl zzBb = new zzfl();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zza extends Exception {
        public zza(String str) {
            super(str);
        }
    }

    private zzfl() {
        super("com.google.android.gms.ads.InAppPurchaseManagerCreatorImpl");
    }

    private static boolean zzc(Activity activity) throws zza {
        Intent intent = activity.getIntent();
        if (intent.hasExtra("com.google.android.gms.ads.internal.purchase.useClientJar")) {
            return intent.getBooleanExtra("com.google.android.gms.ads.internal.purchase.useClientJar", false);
        }
        throw new zza("InAppPurchaseManager requires the useClientJar flag in intent extras.");
    }

    public static zzfg zze(Activity activity) {
        zzfg zzf;
        try {
            if (zzc(activity)) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Using AdOverlay from the client jar.");
                zzf = new com.google.android.gms.ads.internal.purchase.zze(activity);
            } else {
                zzf = zzBb.zzf(activity);
            }
            return zzf;
        } catch (zza e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC(e.getMessage());
            return null;
        }
    }

    private zzfg zzf(Activity activity) {
        try {
            return zzfg.zza.zzN(zzak(activity).zzd(com.google.android.gms.dynamic.zze.zzw(activity)));
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not create remote InAppPurchaseManager.", e);
            return null;
        } catch (zzg.zza e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not create remote InAppPurchaseManager.", e2);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zzR */
    public zzfh zzd(IBinder iBinder) {
        return zzfh.zza.zzO(iBinder);
    }
}
