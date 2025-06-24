package com.google.android.gms.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.text.TextUtils;
import com.google.android.gms.auth.api.Auth;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zzjl;
/* loaded from: classes.dex */
public final class zzjj extends com.google.android.gms.common.internal.zzi<zzjl> {
    private final Bundle zzOR;

    public zzjj(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Auth.zza zzaVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 16, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzOR = zzaVar == null ? new Bundle() : zzaVar.zzkY();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.auth.api.internal.IAuthService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.auth.service.START";
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresSignIn() {
        com.google.android.gms.common.internal.zze zznK = zznK();
        return (TextUtils.isEmpty(zznK.getAccountName()) || zznK.zzb(Auth.zzOL).isEmpty()) ? false : true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzar */
    public zzjl zzT(IBinder iBinder) {
        return zzjl.zza.zzat(iBinder);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zzkR() {
        return this.zzOR;
    }
}
