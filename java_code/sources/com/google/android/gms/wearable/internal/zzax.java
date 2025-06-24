package com.google.android.gms.wearable.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.Node;
import com.google.android.gms.wearable.NodeApi;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public final class zzax implements NodeApi {

    /* loaded from: classes.dex */
    private static final class zza extends zzf<Status> {
        private NodeApi.NodeListener zzaUI;

        private zza(GoogleApiClient googleApiClient, NodeApi.NodeListener nodeListener) {
            super(googleApiClient);
            this.zzaUI = nodeListener;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zza(this, this.zzaUI);
            this.zzaUI = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaUI = null;
            return status;
        }
    }

    /* loaded from: classes.dex */
    public static class zzb implements NodeApi.GetConnectedNodesResult {
        private final Status zzOt;
        private final List<Node> zzaUJ;

        public zzb(Status status, List<Node> list) {
            this.zzOt = status;
            this.zzaUJ = list;
        }

        @Override // com.google.android.gms.wearable.NodeApi.GetConnectedNodesResult
        public List<Node> getNodes() {
            return this.zzaUJ;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    public static class zzc implements NodeApi.GetLocalNodeResult {
        private final Status zzOt;
        private final Node zzaUK;

        public zzc(Status status, Node node) {
            this.zzOt = status;
            this.zzaUK = node;
        }

        @Override // com.google.android.gms.wearable.NodeApi.GetLocalNodeResult
        public Node getNode() {
            return this.zzaUK;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    @Override // com.google.android.gms.wearable.NodeApi
    public PendingResult<Status> addListener(GoogleApiClient client, NodeApi.NodeListener listener) {
        return client.zza((GoogleApiClient) new zza(client, listener));
    }

    @Override // com.google.android.gms.wearable.NodeApi
    public PendingResult<NodeApi.GetConnectedNodesResult> getConnectedNodes(GoogleApiClient client) {
        return client.zza((GoogleApiClient) new zzf<NodeApi.GetConnectedNodesResult>(client) { // from class: com.google.android.gms.wearable.internal.zzax.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzn(this);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbj */
            public NodeApi.GetConnectedNodesResult createFailedResult(Status status) {
                return new zzb(status, new ArrayList());
            }
        });
    }

    @Override // com.google.android.gms.wearable.NodeApi
    public PendingResult<NodeApi.GetLocalNodeResult> getLocalNode(GoogleApiClient client) {
        return client.zza((GoogleApiClient) new zzf<NodeApi.GetLocalNodeResult>(client) { // from class: com.google.android.gms.wearable.internal.zzax.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzm(this);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbi */
            public NodeApi.GetLocalNodeResult createFailedResult(Status status) {
                return new zzc(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.NodeApi
    public PendingResult<Status> removeListener(GoogleApiClient client, final NodeApi.NodeListener listener) {
        return client.zza((GoogleApiClient) new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.zzax.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzb(this, listener);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }
}
