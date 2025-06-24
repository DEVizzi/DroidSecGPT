package com.google.android.gms.nearby.messages.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.nearby.messages.internal.zzc;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzf extends com.google.android.gms.common.internal.zzi<zzc> {
    private String zzOe;
    private String zzaGa;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzf(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar, com.google.android.gms.nearby.messages.zze zzeVar2) {
        super(context, looper, 62, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzOe = zzeVar.zzny();
        if (zzeVar2 != null) {
            this.zzaGa = zzeVar2.zzayp;
        }
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.nearby.messages.internal.INearbyMessagesService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.nearby.messages.service.NearbyMessagesService.START";
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresAccount() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzdg */
    public zzc zzT(IBinder iBinder) {
        return zzc.zza.zzdf(iBinder);
    }
}
