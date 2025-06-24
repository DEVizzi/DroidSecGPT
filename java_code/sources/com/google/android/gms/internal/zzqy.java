package com.google.android.gms.internal;

import android.app.Activity;
import android.os.IBinder;
import android.os.RemoteException;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.dynamic.zzg;
import com.google.android.gms.internal.zzqt;
import com.google.android.gms.wallet.fragment.WalletFragmentOptions;
/* loaded from: classes.dex */
public class zzqy extends com.google.android.gms.dynamic.zzg<zzqt> {
    private static zzqy zzaSv;

    protected zzqy() {
        super("com.google.android.gms.wallet.dynamite.WalletDynamiteCreatorImpl");
    }

    private static zzqy zzAM() {
        if (zzaSv == null) {
            zzaSv = new zzqy();
        }
        return zzaSv;
    }

    public static zzqq zza(Activity activity, com.google.android.gms.dynamic.zzc zzcVar, WalletFragmentOptions walletFragmentOptions, zzqr zzqrVar) throws GooglePlayServicesNotAvailableException {
        int isGooglePlayServicesAvailable = GooglePlayServicesUtil.isGooglePlayServicesAvailable(activity);
        if (isGooglePlayServicesAvailable != 0) {
            throw new GooglePlayServicesNotAvailableException(isGooglePlayServicesAvailable);
        }
        try {
            return zzAM().zzak(activity).zza(com.google.android.gms.dynamic.zze.zzw(activity), zzcVar, walletFragmentOptions, zzqrVar);
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        } catch (zzg.zza e2) {
            throw new RuntimeException(e2);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.dynamic.zzg
    /* renamed from: zzdM */
    public zzqt zzd(IBinder iBinder) {
        return zzqt.zza.zzdI(iBinder);
    }
}
