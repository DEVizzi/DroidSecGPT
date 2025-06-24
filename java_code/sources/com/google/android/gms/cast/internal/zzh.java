package com.google.android.gms.cast.internal;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Status;
/* loaded from: classes.dex */
public abstract class zzh extends zzb<Status> {
    public zzh(GoogleApiClient googleApiClient) {
        super(googleApiClient);
    }

    @Override // com.google.android.gms.common.api.AbstractPendingResult
    /* renamed from: zzb */
    public Status createFailedResult(Status status) {
        return status;
    }
}
