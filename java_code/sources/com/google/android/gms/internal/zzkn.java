package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.internal.zzko;
/* loaded from: classes.dex */
public final class zzkn implements zzkm {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends zzkk {
        private final zza.zzb<Status> zzOs;

        public zza(zza.zzb<Status> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.internal.zzkk, com.google.android.gms.internal.zzkq
        public void zzbB(int i) throws RemoteException {
            this.zzOs.zzm(new Status(i));
        }
    }

    @Override // com.google.android.gms.internal.zzkm
    public PendingResult<Status> zzc(GoogleApiClient googleApiClient) {
        return googleApiClient.zzb(new zzko.zza(googleApiClient) { // from class: com.google.android.gms.internal.zzkn.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzkp zzkpVar) throws RemoteException {
                zzkpVar.zznM().zza(new zza(this));
            }
        });
    }
}
