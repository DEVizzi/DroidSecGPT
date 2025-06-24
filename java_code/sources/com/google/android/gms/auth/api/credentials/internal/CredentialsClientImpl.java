package com.google.android.gms.auth.api.credentials.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import com.google.android.gms.auth.api.credentials.internal.ICredentialsService;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.internal.zzi;
/* loaded from: classes.dex */
public final class CredentialsClientImpl extends zzi<ICredentialsService> {
    public static final String ACTION_START_SERVICE = "com.google.android.gms.auth.api.credentials.service.START";

    public CredentialsClientImpl(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionListener, GoogleApiClient.OnConnectionFailedListener connectionFailedListener) {
        super(context, looper, 68, connectionListener, connectionFailedListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: createServiceInterface */
    public ICredentialsService zzT(IBinder binder) {
        return ICredentialsService.zza.zzaq(binder);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.auth.api.credentials.internal.ICredentialsService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return ACTION_START_SERVICE;
    }
}
