package com.google.android.gms.internal;

import android.content.Context;
import android.os.Looper;
import android.os.RemoteException;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.nearby.Nearby;
import com.google.android.gms.nearby.connection.AppMetadata;
import com.google.android.gms.nearby.connection.Connections;
import java.util.List;
/* loaded from: classes.dex */
public final class zzoq implements Connections {
    public static final Api.ClientKey<zzop> zzNX = new Api.ClientKey<>();
    public static final Api.zza<zzop, Api.ApiOptions.NoOptions> zzNY = new Api.zza<zzop, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.internal.zzoq.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzq */
        public zzop zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzop(context, looper, connectionCallbacks, onConnectionFailedListener);
        }
    };

    /* loaded from: classes.dex */
    private static abstract class zza<R extends Result> extends zza.AbstractC0032zza<R, zzop> {
        public zza(GoogleApiClient googleApiClient) {
            super(zzoq.zzNX, googleApiClient);
        }
    }

    /* loaded from: classes.dex */
    private static abstract class zzb extends zza<Connections.StartAdvertisingResult> {
        private zzb(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaM */
        public Connections.StartAdvertisingResult createFailedResult(final Status status) {
            return new Connections.StartAdvertisingResult() { // from class: com.google.android.gms.internal.zzoq.zzb.1
                @Override // com.google.android.gms.nearby.connection.Connections.StartAdvertisingResult
                public String getLocalEndpointName() {
                    return null;
                }

                @Override // com.google.android.gms.common.api.Result
                public Status getStatus() {
                    return status;
                }
            };
        }
    }

    /* loaded from: classes.dex */
    private static abstract class zzc extends zza<Status> {
        private zzc(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            return status;
        }
    }

    public static zzop zzd(GoogleApiClient googleApiClient, boolean z) {
        com.google.android.gms.common.internal.zzu.zzb(googleApiClient != null, "GoogleApiClient parameter is required.");
        com.google.android.gms.common.internal.zzu.zza(googleApiClient.isConnected(), "GoogleApiClient must be connected.");
        return zze(googleApiClient, z);
    }

    public static zzop zze(GoogleApiClient googleApiClient, boolean z) {
        com.google.android.gms.common.internal.zzu.zza(googleApiClient.zza(Nearby.CONNECTIONS_API), "GoogleApiClient is not configured to use the Nearby Connections Api. Pass Nearby.CONNECTIONS_API into GoogleApiClient.Builder#addApi() to use this feature.");
        boolean hasConnectedApi = googleApiClient.hasConnectedApi(Nearby.CONNECTIONS_API);
        if (!z || hasConnectedApi) {
            if (hasConnectedApi) {
                return (zzop) googleApiClient.zza(zzNX);
            }
            return null;
        }
        throw new IllegalStateException("GoogleApiClient has an optional Nearby.CONNECTIONS_API and is not connected to Nearby Connections. Use GoogleApiClient.hasConnectedApi(Nearby.CONNECTIONS_API) to guard this call.");
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public PendingResult<Status> acceptConnectionRequest(GoogleApiClient apiClient, final String remoteEndpointId, final byte[] payload, Connections.MessageListener messageListener) {
        final com.google.android.gms.common.api.zzi zzo = apiClient.zzo(messageListener);
        return apiClient.zzb(new zzc(apiClient) { // from class: com.google.android.gms.internal.zzoq.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzop zzopVar) throws RemoteException {
                zzopVar.zza(this, remoteEndpointId, payload, zzo);
            }
        });
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void disconnectFromEndpoint(GoogleApiClient apiClient, String remoteEndpointId) {
        zzd(apiClient, false).zzdR(remoteEndpointId);
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public String getLocalDeviceId(GoogleApiClient apiClient) {
        return zzd(apiClient, true).zzwS();
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public String getLocalEndpointId(GoogleApiClient apiClient) {
        return zzd(apiClient, true).zzwR();
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public PendingResult<Status> rejectConnectionRequest(GoogleApiClient apiClient, final String remoteEndpointId) {
        return apiClient.zzb(new zzc(apiClient) { // from class: com.google.android.gms.internal.zzoq.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzop zzopVar) throws RemoteException {
                zzopVar.zzp(this, remoteEndpointId);
            }
        });
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public PendingResult<Status> sendConnectionRequest(GoogleApiClient apiClient, final String name, final String remoteEndpointId, final byte[] payload, Connections.ConnectionResponseCallback connectionResponseCallback, Connections.MessageListener messageListener) {
        final com.google.android.gms.common.api.zzi zzo = apiClient.zzo(connectionResponseCallback);
        final com.google.android.gms.common.api.zzi zzo2 = apiClient.zzo(messageListener);
        return apiClient.zzb(new zzc(apiClient) { // from class: com.google.android.gms.internal.zzoq.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzop zzopVar) throws RemoteException {
                zzopVar.zza(this, name, remoteEndpointId, payload, zzo, zzo2);
            }
        });
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void sendReliableMessage(GoogleApiClient apiClient, String remoteEndpointId, byte[] payload) {
        zzd(apiClient, false).zza(new String[]{remoteEndpointId}, payload);
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void sendReliableMessage(GoogleApiClient apiClient, List<String> remoteEndpointIds, byte[] payload) {
        zzd(apiClient, false).zza((String[]) remoteEndpointIds.toArray(new String[remoteEndpointIds.size()]), payload);
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void sendUnreliableMessage(GoogleApiClient apiClient, String remoteEndpointId, byte[] payload) {
        zzd(apiClient, false).zzb(new String[]{remoteEndpointId}, payload);
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void sendUnreliableMessage(GoogleApiClient apiClient, List<String> remoteEndpointIds, byte[] payload) {
        zzd(apiClient, false).zzb((String[]) remoteEndpointIds.toArray(new String[remoteEndpointIds.size()]), payload);
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public PendingResult<Connections.StartAdvertisingResult> startAdvertising(GoogleApiClient apiClient, final String name, final AppMetadata appMetadata, final long durationMillis, Connections.ConnectionRequestListener connectionRequestListener) {
        final com.google.android.gms.common.api.zzi zzo = apiClient.zzo(connectionRequestListener);
        return apiClient.zzb(new zzb(apiClient) { // from class: com.google.android.gms.internal.zzoq.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzop zzopVar) throws RemoteException {
                zzopVar.zza(this, name, appMetadata, durationMillis, zzo);
            }
        });
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public PendingResult<Status> startDiscovery(GoogleApiClient apiClient, final String serviceId, final long durationMillis, Connections.EndpointDiscoveryListener listener) {
        final com.google.android.gms.common.api.zzi zzo = apiClient.zzo(listener);
        return apiClient.zzb(new zzc(apiClient) { // from class: com.google.android.gms.internal.zzoq.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzop zzopVar) throws RemoteException {
                zzopVar.zza(this, serviceId, durationMillis, zzo);
            }
        });
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void stopAdvertising(GoogleApiClient apiClient) {
        zzd(apiClient, false).zzwT();
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void stopAllEndpoints(GoogleApiClient apiClient) {
        zzd(apiClient, false).zzwU();
    }

    @Override // com.google.android.gms.nearby.connection.Connections
    public void stopDiscovery(GoogleApiClient apiClient, String serviceId) {
        zzd(apiClient, false).zzdQ(serviceId);
    }
}
