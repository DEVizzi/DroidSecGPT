package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.api.zzi;
import com.google.android.gms.internal.zzos;
import com.google.android.gms.nearby.connection.AppMetadata;
import com.google.android.gms.nearby.connection.Connections;
/* loaded from: classes.dex */
public final class zzop extends com.google.android.gms.common.internal.zzi<zzos> {
    private final long zzaoX;

    /* loaded from: classes.dex */
    private static final class zza extends zzb {
        private final zza.zzb<Status> zzOs;

        public zza(zza.zzb<Status> zzbVar, com.google.android.gms.common.api.zzi<Connections.MessageListener> zziVar) {
            super(zziVar);
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzu(zzbVar);
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void zzia(int i) throws RemoteException {
            this.zzOs.zzm(new Status(i));
        }
    }

    /* loaded from: classes.dex */
    private static class zzb extends zzoo {
        private final com.google.android.gms.common.api.zzi<Connections.MessageListener> zzaFr;

        zzb(com.google.android.gms.common.api.zzi<Connections.MessageListener> zziVar) {
            this.zzaFr = zziVar;
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void onDisconnected(final String remoteEndpointId) throws RemoteException {
            this.zzaFr.zza(new zzi.zzb<Connections.MessageListener>() { // from class: com.google.android.gms.internal.zzop.zzb.2
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(Connections.MessageListener messageListener) {
                    messageListener.onDisconnected(remoteEndpointId);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void onMessageReceived(final String remoteEndpointId, final byte[] payload, final boolean isReliable) throws RemoteException {
            this.zzaFr.zza(new zzi.zzb<Connections.MessageListener>() { // from class: com.google.android.gms.internal.zzop.zzb.1
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(Connections.MessageListener messageListener) {
                    messageListener.onMessageReceived(remoteEndpointId, payload, isReliable);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }
    }

    /* loaded from: classes.dex */
    private static final class zzc extends zzb {
        private final zza.zzb<Status> zzOs;
        private final com.google.android.gms.common.api.zzi<Connections.ConnectionResponseCallback> zzaFv;

        public zzc(zza.zzb<Status> zzbVar, com.google.android.gms.common.api.zzi<Connections.ConnectionResponseCallback> zziVar, com.google.android.gms.common.api.zzi<Connections.MessageListener> zziVar2) {
            super(zziVar2);
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzu(zzbVar);
            this.zzaFv = (com.google.android.gms.common.api.zzi) com.google.android.gms.common.internal.zzu.zzu(zziVar);
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void zza(final String str, final int i, final byte[] bArr) throws RemoteException {
            this.zzaFv.zza(new zzi.zzb<Connections.ConnectionResponseCallback>() { // from class: com.google.android.gms.internal.zzop.zzc.1
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(Connections.ConnectionResponseCallback connectionResponseCallback) {
                    connectionResponseCallback.onConnectionResponse(str, new Status(i), bArr);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void zzhZ(int i) throws RemoteException {
            this.zzOs.zzm(new Status(i));
        }
    }

    /* loaded from: classes.dex */
    private static final class zzd extends zzoo {
        private final zza.zzb<Connections.StartAdvertisingResult> zzOs;
        private final com.google.android.gms.common.api.zzi<Connections.ConnectionRequestListener> zzaFx;

        zzd(zza.zzb<Connections.StartAdvertisingResult> zzbVar, com.google.android.gms.common.api.zzi<Connections.ConnectionRequestListener> zziVar) {
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzu(zzbVar);
            this.zzaFx = (com.google.android.gms.common.api.zzi) com.google.android.gms.common.internal.zzu.zzu(zziVar);
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void onConnectionRequest(final String remoteEndpointId, final String remoteDeviceId, final String remoteEndpointName, final byte[] payload) throws RemoteException {
            this.zzaFx.zza(new zzi.zzb<Connections.ConnectionRequestListener>() { // from class: com.google.android.gms.internal.zzop.zzd.1
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(Connections.ConnectionRequestListener connectionRequestListener) {
                    connectionRequestListener.onConnectionRequest(remoteEndpointId, remoteDeviceId, remoteEndpointName, payload);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void zzj(int i, String str) throws RemoteException {
            this.zzOs.zzm(new zze(new Status(i), str));
        }
    }

    /* loaded from: classes.dex */
    private static final class zze implements Connections.StartAdvertisingResult {
        private final Status zzOt;
        private final String zzaFB;

        zze(Status status, String str) {
            this.zzOt = status;
            this.zzaFB = str;
        }

        @Override // com.google.android.gms.nearby.connection.Connections.StartAdvertisingResult
        public String getLocalEndpointName() {
            return this.zzaFB;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    private static final class zzf extends zzoo {
        private final zza.zzb<Status> zzOs;
        private final com.google.android.gms.common.api.zzi<Connections.EndpointDiscoveryListener> zzaFx;

        zzf(zza.zzb<Status> zzbVar, com.google.android.gms.common.api.zzi<Connections.EndpointDiscoveryListener> zziVar) {
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzu(zzbVar);
            this.zzaFx = (com.google.android.gms.common.api.zzi) com.google.android.gms.common.internal.zzu.zzu(zziVar);
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void onEndpointFound(final String endpointId, final String deviceId, final String serviceId, final String name) throws RemoteException {
            this.zzaFx.zza(new zzi.zzb<Connections.EndpointDiscoveryListener>() { // from class: com.google.android.gms.internal.zzop.zzf.1
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(Connections.EndpointDiscoveryListener endpointDiscoveryListener) {
                    endpointDiscoveryListener.onEndpointFound(endpointId, deviceId, serviceId, name);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void onEndpointLost(final String endpointId) throws RemoteException {
            this.zzaFx.zza(new zzi.zzb<Connections.EndpointDiscoveryListener>() { // from class: com.google.android.gms.internal.zzop.zzf.2
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(Connections.EndpointDiscoveryListener endpointDiscoveryListener) {
                    endpointDiscoveryListener.onEndpointLost(endpointId);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }

        @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
        public void zzhX(int i) throws RemoteException {
            this.zzOs.zzm(new Status(i));
        }
    }

    public zzop(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 54, connectionCallbacks, onConnectionFailedListener);
        this.zzaoX = hashCode();
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        if (isConnected()) {
            try {
                zznM().zzE(this.zzaoX);
            } catch (RemoteException e) {
                Log.w("NearbyConnectionsClient", "Failed to notify client disconnect.", e);
            }
        }
        super.disconnect();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.nearby.internal.connection.INearbyConnectionService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.nearby.connection.service.START";
    }

    public void zza(zza.zzb<Status> zzbVar, String str, long j, com.google.android.gms.common.api.zzi<Connections.EndpointDiscoveryListener> zziVar) throws RemoteException {
        zznM().zza(new zzf(zzbVar, zziVar), str, j, this.zzaoX);
    }

    public void zza(zza.zzb<Connections.StartAdvertisingResult> zzbVar, String str, AppMetadata appMetadata, long j, com.google.android.gms.common.api.zzi<Connections.ConnectionRequestListener> zziVar) throws RemoteException {
        zznM().zza(new zzd(zzbVar, zziVar), str, appMetadata, j, this.zzaoX);
    }

    public void zza(zza.zzb<Status> zzbVar, String str, String str2, byte[] bArr, com.google.android.gms.common.api.zzi<Connections.ConnectionResponseCallback> zziVar, com.google.android.gms.common.api.zzi<Connections.MessageListener> zziVar2) throws RemoteException {
        zznM().zza(new zzc(zzbVar, zziVar, zziVar2), str, str2, bArr, this.zzaoX);
    }

    public void zza(zza.zzb<Status> zzbVar, String str, byte[] bArr, com.google.android.gms.common.api.zzi<Connections.MessageListener> zziVar) throws RemoteException {
        zznM().zza(new zza(zzbVar, zziVar), str, bArr, this.zzaoX);
    }

    public void zza(String[] strArr, byte[] bArr) {
        try {
            zznM().zza(strArr, bArr, this.zzaoX);
        } catch (RemoteException e) {
            Log.w("NearbyConnectionsClient", "Couldn't send reliable message", e);
        }
    }

    public void zzb(String[] strArr, byte[] bArr) {
        try {
            zznM().zzb(strArr, bArr, this.zzaoX);
        } catch (RemoteException e) {
            Log.w("NearbyConnectionsClient", "Couldn't send unreliable message", e);
        }
    }

    public void zzdQ(String str) {
        try {
            zznM().zzf(str, this.zzaoX);
        } catch (RemoteException e) {
            Log.w("NearbyConnectionsClient", "Couldn't stop discovery", e);
        }
    }

    public void zzdR(String str) {
        try {
            zznM().zzg(str, this.zzaoX);
        } catch (RemoteException e) {
            Log.w("NearbyConnectionsClient", "Couldn't disconnect from endpoint", e);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzda */
    public zzos zzT(IBinder iBinder) {
        return zzos.zza.zzdc(iBinder);
    }

    public void zzp(final zza.zzb<Status> zzbVar, String str) throws RemoteException {
        zznM().zza(new zzoo() { // from class: com.google.android.gms.internal.zzop.1
            @Override // com.google.android.gms.internal.zzoo, com.google.android.gms.internal.zzor
            public void zzib(int i) throws RemoteException {
                zzbVar.zzm(new Status(i));
            }
        }, str, this.zzaoX);
    }

    public String zzwR() {
        try {
            return zznM().zzQ(this.zzaoX);
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }

    public String zzwS() {
        try {
            return zznM().zzwS();
        } catch (RemoteException e) {
            throw new RuntimeException(e);
        }
    }

    public void zzwT() {
        try {
            zznM().zzN(this.zzaoX);
        } catch (RemoteException e) {
            Log.w("NearbyConnectionsClient", "Couldn't stop advertising", e);
        }
    }

    public void zzwU() {
        try {
            zznM().zzP(this.zzaoX);
        } catch (RemoteException e) {
            Log.w("NearbyConnectionsClient", "Couldn't stop all endpoints", e);
        }
    }
}
