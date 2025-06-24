package com.google.android.gms.common.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
/* loaded from: classes.dex */
public class zzz<T extends IInterface> extends zzi<T> {
    private final Api.zzb<T> zzabf;

    public zzz(Context context, Looper looper, int i, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, zze zzeVar, Api.zzb zzbVar) {
        super(context, looper, i, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzabf = zzbVar;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return this.zzabf.getServiceDescriptor();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return this.zzabf.getStartServiceAction();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected T zzT(IBinder iBinder) {
        return this.zzabf.zzT(iBinder);
    }
}
