package com.google.android.gms.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zziz;
/* loaded from: classes.dex */
public class zzix extends com.google.android.gms.common.internal.zzi<zziz> {
    private final String zzOd;
    private final String zzOe;

    public zzix(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar) {
        super(context, looper, 77, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzOd = zzeVar.zznz();
        this.zzOe = zzeVar.zzny();
    }

    private Bundle zzkS() {
        Bundle bundle = new Bundle();
        bundle.putString("authPackage", this.zzOe);
        return bundle;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.appinvite.internal.IAppInviteService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.appinvite.service.START";
    }

    public void zza(zziy zziyVar, String str) {
        try {
            zznM().zza(zziyVar, str);
        } catch (RemoteException e) {
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzag */
    public zziz zzT(IBinder iBinder) {
        return zziz.zza.zzai(iBinder);
    }

    public void zzb(zziy zziyVar, String str) {
        try {
            zznM().zzb(zziyVar, str);
        } catch (RemoteException e) {
        }
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String zzkQ() {
        return this.zzOd;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zzkR() {
        return zzkS();
    }
}
