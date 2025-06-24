package com.google.android.gms.cast.internal;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
/* loaded from: classes.dex */
public abstract class zzb<R extends Result> extends zza.AbstractC0032zza<R, zze> {
    public zzb(GoogleApiClient googleApiClient) {
        super(zzk.zzNX, googleApiClient);
    }

    public void zzaL(int i) {
        setResult(createFailedResult(new Status(i)));
    }

    public void zzd(int i, String str) {
        setResult(createFailedResult(new Status(i, str, null)));
    }
}
