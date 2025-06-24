package com.google.android.gms.nearby.connection;

import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import java.util.Arrays;
import java.util.List;
/* loaded from: classes.dex */
public interface Connections {
    public static final long DURATION_INDEFINITE = 0;
    public static final int MAX_RELIABLE_MESSAGE_LEN = 4096;
    public static final int MAX_UNRELIABLE_MESSAGE_LEN = 1168;
    public static final List<Integer> zzaFo = Arrays.asList(1, 2);

    /* loaded from: classes.dex */
    public interface ConnectionRequestListener {
        void onConnectionRequest(String str, String str2, String str3, byte[] bArr);
    }

    /* loaded from: classes.dex */
    public interface ConnectionResponseCallback {
        void onConnectionResponse(String str, Status status, byte[] bArr);
    }

    /* loaded from: classes.dex */
    public interface EndpointDiscoveryListener {
        void onEndpointFound(String str, String str2, String str3, String str4);

        void onEndpointLost(String str);
    }

    /* loaded from: classes.dex */
    public interface MessageListener {
        void onDisconnected(String str);

        void onMessageReceived(String str, byte[] bArr, boolean z);
    }

    /* loaded from: classes.dex */
    public interface StartAdvertisingResult extends Result {
        String getLocalEndpointName();
    }

    PendingResult<Status> acceptConnectionRequest(GoogleApiClient googleApiClient, String str, byte[] bArr, MessageListener messageListener);

    void disconnectFromEndpoint(GoogleApiClient googleApiClient, String str);

    String getLocalDeviceId(GoogleApiClient googleApiClient);

    String getLocalEndpointId(GoogleApiClient googleApiClient);

    PendingResult<Status> rejectConnectionRequest(GoogleApiClient googleApiClient, String str);

    PendingResult<Status> sendConnectionRequest(GoogleApiClient googleApiClient, String str, String str2, byte[] bArr, ConnectionResponseCallback connectionResponseCallback, MessageListener messageListener);

    void sendReliableMessage(GoogleApiClient googleApiClient, String str, byte[] bArr);

    void sendReliableMessage(GoogleApiClient googleApiClient, List<String> list, byte[] bArr);

    void sendUnreliableMessage(GoogleApiClient googleApiClient, String str, byte[] bArr);

    void sendUnreliableMessage(GoogleApiClient googleApiClient, List<String> list, byte[] bArr);

    PendingResult<StartAdvertisingResult> startAdvertising(GoogleApiClient googleApiClient, String str, AppMetadata appMetadata, long j, ConnectionRequestListener connectionRequestListener);

    PendingResult<Status> startDiscovery(GoogleApiClient googleApiClient, String str, long j, EndpointDiscoveryListener endpointDiscoveryListener);

    void stopAdvertising(GoogleApiClient googleApiClient);

    void stopAllEndpoints(GoogleApiClient googleApiClient);

    void stopDiscovery(GoogleApiClient googleApiClient, String str);
}
