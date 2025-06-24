package com.google.android.gms.internal;

import android.content.Context;
import android.os.IInterface;
import android.os.Looper;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import java.util.Set;
/* loaded from: classes.dex */
public abstract class zzlw<T extends IInterface> extends com.google.android.gms.common.internal.zzi<T> {
    /* JADX INFO: Access modifiers changed from: protected */
    public zzlw(Context context, Looper looper, int i, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar) {
        super(context, looper, i, connectionCallbacks, onConnectionFailedListener, zzeVar);
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresAccount() {
        return true;
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresSignIn() {
        return !zzlv.zzam(getContext());
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Set<Scope> zza(Set<Scope> set) {
        return com.google.android.gms.fitness.zza.zzd(set);
    }
}
