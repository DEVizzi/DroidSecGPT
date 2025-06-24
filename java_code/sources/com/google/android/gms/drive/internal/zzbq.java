package com.google.android.gms.drive.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
/* loaded from: classes.dex */
public class zzbq extends zzd {
    private final zza.zzb<Status> zzOs;

    public zzbq(zza.zzb<Status> zzbVar) {
        this.zzOs = zzbVar;
    }

    @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
    public void onSuccess() throws RemoteException {
        this.zzOs.zzm(Status.zzXP);
    }

    @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
    public void zzt(Status status) throws RemoteException {
        this.zzOs.zzm(status);
    }
}
