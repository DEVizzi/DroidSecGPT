package com.google.android.gms.drive.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.drive.Drive;
import com.google.android.gms.drive.DriveApi;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.DriveResource;
import com.google.android.gms.drive.Metadata;
import com.google.android.gms.drive.MetadataBuffer;
import com.google.android.gms.drive.MetadataChangeSet;
import com.google.android.gms.drive.events.ChangeListener;
import com.google.android.gms.drive.internal.zzq;
import com.google.android.gms.drive.internal.zzr;
import java.util.ArrayList;
import java.util.Set;
/* loaded from: classes.dex */
public class zzz implements DriveResource {
    protected final DriveId zzacT;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends com.google.android.gms.drive.internal.zzd {
        private final zza.zzb<DriveApi.MetadataBufferResult> zzOs;

        public zza(zza.zzb<DriveApi.MetadataBufferResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zza(OnListParentsResponse onListParentsResponse) throws RemoteException {
            this.zzOs.zzm(new zzq.zzf(Status.zzXP, new MetadataBuffer(onListParentsResponse.zzpR()), false));
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zzt(Status status) throws RemoteException {
            this.zzOs.zzm(new zzq.zzf(status, null, false));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzb extends com.google.android.gms.drive.internal.zzd {
        private final zza.zzb<DriveResource.MetadataResult> zzOs;

        public zzb(zza.zzb<DriveResource.MetadataResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zza(OnMetadataResponse onMetadataResponse) throws RemoteException {
            this.zzOs.zzm(new zzc(Status.zzXP, new zzn(onMetadataResponse.zzpS())));
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zzt(Status status) throws RemoteException {
            this.zzOs.zzm(new zzc(status, null));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzc implements DriveResource.MetadataResult {
        private final Status zzOt;
        private final Metadata zzafA;

        public zzc(Status status, Metadata metadata) {
            this.zzOt = status;
            this.zzafA = metadata;
        }

        @Override // com.google.android.gms.drive.DriveResource.MetadataResult
        public Metadata getMetadata() {
            return this.zzafA;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    private abstract class zzd extends zzr<DriveResource.MetadataResult> {
        private zzd(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzA */
        public DriveResource.MetadataResult createFailedResult(Status status) {
            return new zzc(status, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzz(DriveId driveId) {
        this.zzacT = driveId;
    }

    private PendingResult<DriveResource.MetadataResult> zza(GoogleApiClient googleApiClient, final boolean z) {
        return googleApiClient.zza((GoogleApiClient) new zzd(googleApiClient) { // from class: com.google.android.gms.drive.internal.zzz.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new GetMetadataRequest(zzz.this.zzacT, z), new zzb(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> addChangeListener(GoogleApiClient apiClient, ChangeListener listener) {
        return ((zzs) apiClient.zza(Drive.zzNX)).zza(apiClient, this.zzacT, listener);
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> addChangeSubscription(GoogleApiClient apiClient) {
        return ((zzs) apiClient.zza(Drive.zzNX)).zza(apiClient, this.zzacT);
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> delete(GoogleApiClient apiClient) {
        return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzz.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new DeleteResourceRequest(zzz.this.zzacT), new zzbq(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveResource
    public DriveId getDriveId() {
        return this.zzacT;
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<DriveResource.MetadataResult> getMetadata(GoogleApiClient apiClient) {
        return zza(apiClient, false);
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<DriveApi.MetadataBufferResult> listParents(GoogleApiClient apiClient) {
        return apiClient.zza((GoogleApiClient) new zzq.zzg(apiClient) { // from class: com.google.android.gms.drive.internal.zzz.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new ListParentsRequest(zzz.this.zzacT), new zza(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> removeChangeListener(GoogleApiClient apiClient, ChangeListener listener) {
        return ((zzs) apiClient.zza(Drive.zzNX)).zzb(apiClient, this.zzacT, listener);
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> removeChangeSubscription(GoogleApiClient apiClient) {
        return ((zzs) apiClient.zza(Drive.zzNX)).zzb(apiClient, this.zzacT);
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> setParents(GoogleApiClient apiClient, Set<DriveId> parentIds) {
        if (parentIds == null) {
            throw new IllegalArgumentException("ParentIds must be provided.");
        }
        if (parentIds.isEmpty()) {
            throw new IllegalArgumentException("ParentIds must contain at least one parent.");
        }
        final ArrayList arrayList = new ArrayList(parentIds);
        return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzz.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new SetResourceParentsRequest(zzz.this.zzacT, arrayList), new zzbq(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> trash(GoogleApiClient apiClient) {
        return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzz.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new TrashResourceRequest(zzz.this.zzacT), new zzbq(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<Status> untrash(GoogleApiClient apiClient) {
        return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzz.7
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new UntrashResourceRequest(zzz.this.zzacT), new zzbq(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveResource
    public PendingResult<DriveResource.MetadataResult> updateMetadata(GoogleApiClient apiClient, final MetadataChangeSet changeSet) {
        if (changeSet == null) {
            throw new IllegalArgumentException("ChangeSet must be provided.");
        }
        return apiClient.zzb(new zzd(apiClient) { // from class: com.google.android.gms.drive.internal.zzz.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                changeSet.zzpm().setContext(zzsVar.getContext());
                zzsVar.zzpB().zza(new UpdateMetadataRequest(zzz.this.zzacT, changeSet.zzpm()), new zzb(this));
            }
        });
    }
}
