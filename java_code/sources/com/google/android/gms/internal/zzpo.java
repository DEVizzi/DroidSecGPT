package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zzpn;
/* loaded from: classes.dex */
public class zzpo extends com.google.android.gms.common.internal.zzi<zzpn> {
    public zzpo(Context context, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar) {
        super(context, context.getMainLooper(), 73, connectionCallbacks, onConnectionFailedListener, zzeVar);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.search.internal.ISearchAuthService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.search.service.SEARCH_AUTH_START";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzdB */
    public zzpn zzT(IBinder iBinder) {
        return zzpn.zza.zzdA(iBinder);
    }
}
