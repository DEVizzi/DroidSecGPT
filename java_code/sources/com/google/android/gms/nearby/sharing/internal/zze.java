package com.google.android.gms.nearby.sharing.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.nearby.sharing.internal.zzd;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zze extends com.google.android.gms.common.internal.zzi<zzd> {
    public zze(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar) {
        super(context, looper, 49, connectionCallbacks, onConnectionFailedListener, zzeVar);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.nearby.sharing.internal.INearbySharingService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.nearby.sharing.service.NearbySharingService.START";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzdl */
    public zzd zzT(IBinder iBinder) {
        return zzd.zza.zzdk(iBinder);
    }
}
