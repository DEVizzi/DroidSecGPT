package com.google.android.gms.ads.internal.request;

import android.content.Context;
import android.os.DeadObjectException;
import android.os.IBinder;
import com.google.android.gms.ads.internal.request.zzi;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public class zze extends com.google.android.gms.common.internal.zzi<zzi> {
    final int zzCk;

    public zze(Context context, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, int i) {
        super(context, context.getMainLooper(), 8, connectionCallbacks, onConnectionFailedListener);
        this.zzCk = i;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.ads.internal.request.IAdRequestService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.ads.service.START";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzS */
    public zzi zzT(IBinder iBinder) {
        return zzi.zza.zzU(iBinder);
    }

    public zzi zzfy() throws DeadObjectException {
        return (zzi) super.zznM();
    }
}
