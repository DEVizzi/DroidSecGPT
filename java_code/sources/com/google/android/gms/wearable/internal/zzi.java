package com.google.android.gms.wearable.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.Channel;
import com.google.android.gms.wearable.ChannelApi;
/* loaded from: classes.dex */
public final class zzi implements ChannelApi {

    /* loaded from: classes.dex */
    static final class zza extends zzf<Status> {
        private final String zzaTK;
        private ChannelApi.ChannelListener zzaTL;

        /* JADX INFO: Access modifiers changed from: package-private */
        public zza(GoogleApiClient googleApiClient, ChannelApi.ChannelListener channelListener, String str) {
            super(googleApiClient);
            this.zzaTL = (ChannelApi.ChannelListener) com.google.android.gms.common.internal.zzu.zzu(channelListener);
            this.zzaTK = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zza(this, this.zzaTL, this.zzaTK);
            this.zzaTL = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaTL = null;
            return status;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzb implements ChannelApi.OpenChannelResult {
        private final Status zzOt;
        private final Channel zzaTM;

        /* JADX INFO: Access modifiers changed from: package-private */
        public zzb(Status status, Channel channel) {
            this.zzOt = (Status) com.google.android.gms.common.internal.zzu.zzu(status);
            this.zzaTM = channel;
        }

        @Override // com.google.android.gms.wearable.ChannelApi.OpenChannelResult
        public Channel getChannel() {
            return this.zzaTM;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    static final class zzc extends zzf<Status> {
        private final String zzaTK;
        private ChannelApi.ChannelListener zzaTL;

        /* JADX INFO: Access modifiers changed from: package-private */
        public zzc(GoogleApiClient googleApiClient, ChannelApi.ChannelListener channelListener, String str) {
            super(googleApiClient);
            this.zzaTL = (ChannelApi.ChannelListener) com.google.android.gms.common.internal.zzu.zzu(channelListener);
            this.zzaTK = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zzb(this, this.zzaTL, this.zzaTK);
            this.zzaTL = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaTL = null;
            return status;
        }
    }

    @Override // com.google.android.gms.wearable.ChannelApi
    public PendingResult<Status> addListener(GoogleApiClient client, ChannelApi.ChannelListener listener) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(listener, "listener is null");
        return client.zza((GoogleApiClient) new zza(client, listener, null));
    }

    @Override // com.google.android.gms.wearable.ChannelApi
    public PendingResult<ChannelApi.OpenChannelResult> openChannel(GoogleApiClient client, final String nodeId, final String path) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(nodeId, "nodeId is null");
        com.google.android.gms.common.internal.zzu.zzb(path, "path is null");
        return client.zzb(new zzf<ChannelApi.OpenChannelResult>(client) { // from class: com.google.android.gms.wearable.internal.zzi.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zze(this, nodeId, path);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzba */
            public ChannelApi.OpenChannelResult createFailedResult(Status status) {
                return new zzb(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.ChannelApi
    public PendingResult<Status> removeListener(GoogleApiClient client, ChannelApi.ChannelListener listener) {
        com.google.android.gms.common.internal.zzu.zzb(client, "client is null");
        com.google.android.gms.common.internal.zzu.zzb(listener, "listener is null");
        return client.zza((GoogleApiClient) new zzc(client, listener, null));
    }
}
