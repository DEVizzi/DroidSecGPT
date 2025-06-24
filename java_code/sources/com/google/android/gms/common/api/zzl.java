package com.google.android.gms.common.api;

import android.os.Looper;
/* loaded from: classes.dex */
public class zzl extends AbstractPendingResult<Status> {
    public zzl(Looper looper) {
        super(looper);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.api.AbstractPendingResult
    /* renamed from: zzb */
    public Status createFailedResult(Status status) {
        return status;
    }
}
