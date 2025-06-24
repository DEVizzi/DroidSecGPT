package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zzou;
/* loaded from: classes.dex */
public class zzow extends com.google.android.gms.common.internal.zzi<zzou> {
    public zzow(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 3, connectionCallbacks, onConnectionFailedListener);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.panorama.internal.IPanoramaService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.panorama.service.START";
    }

    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzdo */
    public zzou zzT(IBinder iBinder) {
        return zzou.zza.zzdn(iBinder);
    }
}
