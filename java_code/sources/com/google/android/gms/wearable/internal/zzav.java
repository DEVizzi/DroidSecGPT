package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.MessageApi;
/* loaded from: classes.dex */
public final class zzav implements MessageApi {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zza extends zzf<Status> {
        private MessageApi.MessageListener zzaUF;
        private IntentFilter[] zzaUk;

        private zza(GoogleApiClient googleApiClient, MessageApi.MessageListener messageListener, IntentFilter[] intentFilterArr) {
            super(googleApiClient);
            this.zzaUF = messageListener;
            this.zzaUk = intentFilterArr;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zza(this, this.zzaUF, this.zzaUk);
            this.zzaUF = null;
            this.zzaUk = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaUF = null;
            this.zzaUk = null;
            return status;
        }
    }

    /* loaded from: classes.dex */
    public static class zzb implements MessageApi.SendMessageResult {
        private final Status zzOt;
        private final int zzacR;

        public zzb(Status status, int i) {
            this.zzOt = status;
            this.zzacR = i;
        }

        @Override // com.google.android.gms.wearable.MessageApi.SendMessageResult
        public int getRequestId() {
            return this.zzacR;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, MessageApi.MessageListener messageListener, IntentFilter[] intentFilterArr) {
        return googleApiClient.zza((GoogleApiClient) new zza(googleApiClient, messageListener, intentFilterArr));
    }

    @Override // com.google.android.gms.wearable.MessageApi
    public PendingResult<Status> addListener(GoogleApiClient client, MessageApi.MessageListener listener) {
        return zza(client, listener, null);
    }

    @Override // com.google.android.gms.wearable.MessageApi
    public PendingResult<Status> removeListener(GoogleApiClient client, final MessageApi.MessageListener listener) {
        return client.zza((GoogleApiClient) new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.zzav.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, listener);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    @Override // com.google.android.gms.wearable.MessageApi
    public PendingResult<MessageApi.SendMessageResult> sendMessage(GoogleApiClient client, final String nodeId, final String action, final byte[] data) {
        return client.zza((GoogleApiClient) new zzf<MessageApi.SendMessageResult>(client) { // from class: com.google.android.gms.wearable.internal.zzav.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, nodeId, action, data);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbh */
            public MessageApi.SendMessageResult createFailedResult(Status status) {
                return new zzb(status, -1);
            }
        });
    }
}
