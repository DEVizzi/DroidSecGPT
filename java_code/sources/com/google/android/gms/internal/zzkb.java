package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import com.google.android.gms.cast.CastDevice;
import com.google.android.gms.cast.CastRemoteDisplay;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.zzkd;
import com.google.android.gms.internal.zzke;
/* loaded from: classes.dex */
public class zzkb extends com.google.android.gms.common.internal.zzi<zzkd> implements IBinder.DeathRecipient {
    private static final com.google.android.gms.cast.internal.zzl zzQW = new com.google.android.gms.cast.internal.zzl("CastRemoteDisplayClientImpl");
    private CastDevice zzQH;
    private CastRemoteDisplay.CastRemoteDisplaySessionCallbacks zzVB;

    public zzkb(Context context, Looper looper, CastDevice castDevice, CastRemoteDisplay.CastRemoteDisplaySessionCallbacks castRemoteDisplaySessionCallbacks, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 83, connectionCallbacks, onConnectionFailedListener);
        this.zzVB = castRemoteDisplaySessionCallbacks;
        this.zzQH = castDevice;
    }

    @Override // android.os.IBinder.DeathRecipient
    public void binderDied() {
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        try {
            zznM().disconnect();
        } catch (RemoteException e) {
        } finally {
            super.disconnect();
        }
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.cast.remote_display.ICastRemoteDisplayService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.cast.remote_display.service.START";
    }

    public void zza(zzkc zzkcVar) throws RemoteException {
        zzQW.zzb("stopRemoteDisplay", new Object[0]);
        zznM().zza(zzkcVar);
    }

    public void zza(zzkc zzkcVar, int i) throws RemoteException {
        zznM().zza(zzkcVar, i);
    }

    public void zza(zzkc zzkcVar, final zzke zzkeVar, String str) throws RemoteException {
        zzQW.zzb("startRemoteDisplay", new Object[0]);
        zznM().zza(zzkcVar, new zzke.zza() { // from class: com.google.android.gms.internal.zzkb.1
            @Override // com.google.android.gms.internal.zzke
            public void zzaR(int i) throws RemoteException {
                zzkb.zzQW.zzb("onRemoteDisplayEnded", new Object[0]);
                if (zzkeVar != null) {
                    zzkeVar.zzaR(i);
                }
                if (zzkb.this.zzVB != null) {
                    zzkb.this.zzVB.onRemoteDisplayEnded(new Status(i));
                }
            }
        }, this.zzQH.getDeviceId(), str);
    }

    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzay */
    public zzkd zzT(IBinder iBinder) {
        return zzkd.zza.zzaA(iBinder);
    }
}
