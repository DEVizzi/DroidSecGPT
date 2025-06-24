package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.ads.mediation.MediationAdapter;
import com.google.ads.mediation.MediationServerParameters;
import com.google.android.gms.ads.mediation.NetworkExtras;
import com.google.android.gms.ads.mediation.customevent.CustomEvent;
import com.google.android.gms.internal.zzef;
import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public final class zzee extends zzef.zza {
    private Map<Class<? extends NetworkExtras>, NetworkExtras> zzyd;

    private <NETWORK_EXTRAS extends com.google.ads.mediation.NetworkExtras, SERVER_PARAMETERS extends MediationServerParameters> zzeg zzaa(String str) throws RemoteException {
        try {
            Class<?> cls = Class.forName(str, false, zzee.class.getClassLoader());
            if (MediationAdapter.class.isAssignableFrom(cls)) {
                MediationAdapter mediationAdapter = (MediationAdapter) cls.newInstance();
                return new zzel(mediationAdapter, (com.google.ads.mediation.NetworkExtras) this.zzyd.get(mediationAdapter.getAdditionalParametersType()));
            } else if (com.google.android.gms.ads.mediation.MediationAdapter.class.isAssignableFrom(cls)) {
                return new zzej((com.google.android.gms.ads.mediation.MediationAdapter) cls.newInstance());
            } else {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not instantiate mediation adapter: " + str + " (not a valid adapter).");
                throw new RemoteException();
            }
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not instantiate mediation adapter: " + str + ". " + th.getMessage());
            throw new RemoteException();
        }
    }

    @Override // com.google.android.gms.internal.zzef
    public zzeg zzY(String str) throws RemoteException {
        return zzaa(str);
    }

    @Override // com.google.android.gms.internal.zzef
    public boolean zzZ(String str) throws RemoteException {
        try {
            return CustomEvent.class.isAssignableFrom(Class.forName(str, false, zzee.class.getClassLoader()));
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Could not load custom event implementation class: " + str + ", assuming old implementation.");
            return false;
        }
    }

    public void zzf(Map<Class<? extends NetworkExtras>, NetworkExtras> map) {
        this.zzyd = map;
    }
}
