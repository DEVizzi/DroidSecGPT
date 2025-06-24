package com.google.android.gms.wearable.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.wearable.CapabilityApi;
import com.google.android.gms.wearable.CapabilityInfo;
import com.google.android.gms.wearable.Node;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public class zzg implements CapabilityApi {

    /* loaded from: classes.dex */
    private static final class zza extends com.google.android.gms.wearable.internal.zzf<Status> {
        private CapabilityApi.CapabilityListener zzaTC;
        private String zzaTD;

        private zza(GoogleApiClient googleApiClient, CapabilityApi.CapabilityListener capabilityListener, String str) {
            super(googleApiClient);
            this.zzaTC = capabilityListener;
            this.zzaTD = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zza(this, this.zzaTC, this.zzaTD);
            this.zzaTC = null;
            this.zzaTD = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaTC = null;
            this.zzaTD = null;
            return status;
        }
    }

    /* loaded from: classes.dex */
    public static class zzb implements CapabilityApi.AddLocalCapabilityResult, CapabilityApi.RemoveLocalCapabilityResult {
        private final Status zzOt;

        public zzb(Status status) {
            this.zzOt = status;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    public static class zzc implements CapabilityInfo {
        private final String mName;
        private final Set<Node> zzaTE;

        public zzc(CapabilityInfo capabilityInfo) {
            this(capabilityInfo.getName(), capabilityInfo.getNodes());
        }

        public zzc(String str, Set<Node> set) {
            this.mName = str;
            this.zzaTE = set;
        }

        @Override // com.google.android.gms.wearable.CapabilityInfo
        public String getName() {
            return this.mName;
        }

        @Override // com.google.android.gms.wearable.CapabilityInfo
        public Set<Node> getNodes() {
            return this.zzaTE;
        }
    }

    /* loaded from: classes.dex */
    public static class zzd implements CapabilityApi.GetAllCapabilitiesResult {
        private final Status zzOt;
        private final Map<String, CapabilityInfo> zzaTF;

        public zzd(Status status, Map<String, CapabilityInfo> map) {
            this.zzOt = status;
            this.zzaTF = map;
        }

        @Override // com.google.android.gms.wearable.CapabilityApi.GetAllCapabilitiesResult
        public Map<String, CapabilityInfo> getAllCapabilities() {
            return this.zzaTF;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    public static class zze implements CapabilityApi.GetCapabilityResult {
        private final Status zzOt;
        private final CapabilityInfo zzaTG;

        public zze(Status status, CapabilityInfo capabilityInfo) {
            this.zzOt = status;
            this.zzaTG = capabilityInfo;
        }

        @Override // com.google.android.gms.wearable.CapabilityApi.GetCapabilityResult
        public CapabilityInfo getCapability() {
            return this.zzaTG;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    private static final class zzf extends com.google.android.gms.wearable.internal.zzf<Status> {
        private CapabilityApi.CapabilityListener zzaTC;
        private String zzaTD;

        private zzf(GoogleApiClient googleApiClient, CapabilityApi.CapabilityListener capabilityListener, String str) {
            super(googleApiClient);
            this.zzaTC = capabilityListener;
            this.zzaTD = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zzb(this, this.zzaTC, this.zzaTD);
            this.zzaTC = null;
            this.zzaTD = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaTC = null;
            this.zzaTD = null;
            return status;
        }
    }

    @Override // com.google.android.gms.wearable.CapabilityApi
    public PendingResult<Status> addCapabilityListener(GoogleApiClient client, CapabilityApi.CapabilityListener listener, String capability) {
        return client.zza((GoogleApiClient) new zza(client, listener, capability));
    }

    @Override // com.google.android.gms.wearable.CapabilityApi
    public PendingResult<CapabilityApi.AddLocalCapabilityResult> addLocalCapability(GoogleApiClient client, final String capability) {
        return client.zza((GoogleApiClient) new com.google.android.gms.wearable.internal.zzf<CapabilityApi.AddLocalCapabilityResult>(client) { // from class: com.google.android.gms.wearable.internal.zzg.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzr(this, capability);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzaY */
            public CapabilityApi.AddLocalCapabilityResult createFailedResult(Status status) {
                return new zzb(status);
            }
        });
    }

    @Override // com.google.android.gms.wearable.CapabilityApi
    public PendingResult<CapabilityApi.GetAllCapabilitiesResult> getAllCapabilities(GoogleApiClient client, final int filter) {
        return client.zza((GoogleApiClient) new com.google.android.gms.wearable.internal.zzf<CapabilityApi.GetAllCapabilitiesResult>(client) { // from class: com.google.android.gms.wearable.internal.zzg.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzd(this, filter);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzaX */
            public CapabilityApi.GetAllCapabilitiesResult createFailedResult(Status status) {
                return new zzd(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.CapabilityApi
    public PendingResult<CapabilityApi.GetCapabilityResult> getCapability(GoogleApiClient client, final String capability, final int filter) {
        return client.zza((GoogleApiClient) new com.google.android.gms.wearable.internal.zzf<CapabilityApi.GetCapabilityResult>(client) { // from class: com.google.android.gms.wearable.internal.zzg.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzg(this, capability, filter);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzaW */
            public CapabilityApi.GetCapabilityResult createFailedResult(Status status) {
                return new zze(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.CapabilityApi
    public PendingResult<Status> removeCapabilityListener(GoogleApiClient client, CapabilityApi.CapabilityListener listener, String capability) {
        return client.zza((GoogleApiClient) new zzf(client, listener, capability));
    }

    @Override // com.google.android.gms.wearable.CapabilityApi
    public PendingResult<CapabilityApi.RemoveLocalCapabilityResult> removeLocalCapability(GoogleApiClient client, final String capability) {
        return client.zza((GoogleApiClient) new com.google.android.gms.wearable.internal.zzf<CapabilityApi.RemoveLocalCapabilityResult>(client) { // from class: com.google.android.gms.wearable.internal.zzg.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzs(this, capability);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzaZ */
            public CapabilityApi.RemoveLocalCapabilityResult createFailedResult(Status status) {
                return new zzb(status);
            }
        });
    }
}
