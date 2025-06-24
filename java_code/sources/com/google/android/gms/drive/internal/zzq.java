package com.google.android.gms.drive.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Releasable;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.drive.CreateFileActivityBuilder;
import com.google.android.gms.drive.Drive;
import com.google.android.gms.drive.DriveApi;
import com.google.android.gms.drive.DriveContents;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.drive.DriveFolder;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.MetadataBuffer;
import com.google.android.gms.drive.OpenFileActivityBuilder;
import com.google.android.gms.drive.internal.zzr;
import com.google.android.gms.drive.query.Query;
import java.util.List;
/* loaded from: classes.dex */
public class zzq implements DriveApi {

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza implements Releasable, DriveApi.DriveContentsResult {
        private final Status zzOt;
        private final DriveContents zzacW;

        public zza(Status status, DriveContents driveContents) {
            this.zzOt = status;
            this.zzacW = driveContents;
        }

        @Override // com.google.android.gms.drive.DriveApi.DriveContentsResult
        public DriveContents getDriveContents() {
            return this.zzacW;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzacW != null) {
                this.zzacW.zzpf();
            }
        }
    }

    /* loaded from: classes.dex */
    static abstract class zzb extends zzr<DriveApi.DriveContentsResult> {
        /* JADX INFO: Access modifiers changed from: package-private */
        public zzb(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzu */
        public DriveApi.DriveContentsResult createFailedResult(Status status) {
            return new zza(status, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zzc extends com.google.android.gms.drive.internal.zzd {
        private final zza.zzb<DriveApi.DriveIdResult> zzOs;

        public zzc(zza.zzb<DriveApi.DriveIdResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zza(OnDriveIdResponse onDriveIdResponse) throws RemoteException {
            this.zzOs.zzm(new zzd(Status.zzXP, onDriveIdResponse.getDriveId()));
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zza(OnMetadataResponse onMetadataResponse) throws RemoteException {
            this.zzOs.zzm(new zzd(Status.zzXP, new zzn(onMetadataResponse.zzpS()).getDriveId()));
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zzt(Status status) throws RemoteException {
            this.zzOs.zzm(new zzd(status, null));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzd implements DriveApi.DriveIdResult {
        private final Status zzOt;
        private final DriveId zzacT;

        public zzd(Status status, DriveId driveId) {
            this.zzOt = status;
            this.zzacT = driveId;
        }

        @Override // com.google.android.gms.drive.DriveApi.DriveIdResult
        public DriveId getDriveId() {
            return this.zzacT;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    static abstract class zze extends zzr<DriveApi.DriveIdResult> {
        zze(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzv */
        public DriveApi.DriveIdResult createFailedResult(Status status) {
            return new zzd(status, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zzf implements DriveApi.MetadataBufferResult {
        private final Status zzOt;
        private final MetadataBuffer zzaeK;
        private final boolean zzaeL;

        public zzf(Status status, MetadataBuffer metadataBuffer, boolean z) {
            this.zzOt = status;
            this.zzaeK = metadataBuffer;
            this.zzaeL = z;
        }

        @Override // com.google.android.gms.drive.DriveApi.MetadataBufferResult
        public MetadataBuffer getMetadataBuffer() {
            return this.zzaeK;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzaeK != null) {
                this.zzaeK.release();
            }
        }
    }

    /* loaded from: classes.dex */
    static abstract class zzg extends zzr<DriveApi.MetadataBufferResult> {
        /* JADX INFO: Access modifiers changed from: package-private */
        public zzg(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzw */
        public DriveApi.MetadataBufferResult createFailedResult(Status status) {
            return new zzf(status, null, false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzh extends com.google.android.gms.drive.internal.zzd {
        private final zza.zzb<DriveApi.DriveContentsResult> zzOs;

        public zzh(zza.zzb<DriveApi.DriveContentsResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zza(OnContentsResponse onContentsResponse) throws RemoteException {
            this.zzOs.zzm(new zza(Status.zzXP, new zzt(onContentsResponse.zzpJ())));
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zzt(Status status) throws RemoteException {
            this.zzOs.zzm(new zza(status, null));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzi extends com.google.android.gms.drive.internal.zzd {
        private final zza.zzb<DriveApi.MetadataBufferResult> zzOs;

        public zzi(zza.zzb<DriveApi.MetadataBufferResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zza(OnListEntriesResponse onListEntriesResponse) throws RemoteException {
            this.zzOs.zzm(new zzf(Status.zzXP, new MetadataBuffer(onListEntriesResponse.zzpP()), onListEntriesResponse.zzpQ()));
        }

        @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
        public void zzt(Status status) throws RemoteException {
            this.zzOs.zzm(new zzf(status, null, false));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zzj extends zzr.zza {
        /* JADX INFO: Access modifiers changed from: package-private */
        public zzj(GoogleApiClient googleApiClient, Status status) {
            super(googleApiClient);
            setResult(status);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzs zzsVar) {
        }
    }

    @Override // com.google.android.gms.drive.DriveApi
    public PendingResult<Status> cancelPendingActions(GoogleApiClient apiClient, List<String> trackingTags) {
        return ((zzs) apiClient.zza(Drive.zzNX)).cancelPendingActions(apiClient, trackingTags);
    }

    @Override // com.google.android.gms.drive.DriveApi
    public PendingResult<DriveApi.DriveIdResult> fetchDriveId(GoogleApiClient apiClient, final String resourceId) {
        return apiClient.zza((GoogleApiClient) new zze(apiClient) { // from class: com.google.android.gms.drive.internal.zzq.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new GetMetadataRequest(DriveId.zzcs(resourceId), false), new zzc(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveApi
    public DriveFolder getAppFolder(GoogleApiClient apiClient) {
        if (apiClient.isConnected()) {
            DriveId zzpD = ((zzs) apiClient.zza(Drive.zzNX)).zzpD();
            if (zzpD != null) {
                return new zzw(zzpD);
            }
            return null;
        }
        throw new IllegalStateException("Client must be connected");
    }

    @Override // com.google.android.gms.drive.DriveApi
    public DriveFile getFile(GoogleApiClient apiClient, DriveId driveId) {
        if (driveId == null) {
            throw new IllegalArgumentException("Id must be provided.");
        }
        if (apiClient.isConnected()) {
            return new zzu(driveId);
        }
        throw new IllegalStateException("Client must be connected");
    }

    @Override // com.google.android.gms.drive.DriveApi
    public DriveFolder getFolder(GoogleApiClient apiClient, DriveId driveId) {
        if (driveId == null) {
            throw new IllegalArgumentException("Id must be provided.");
        }
        if (apiClient.isConnected()) {
            return new zzw(driveId);
        }
        throw new IllegalStateException("Client must be connected");
    }

    @Override // com.google.android.gms.drive.DriveApi
    public DriveFolder getRootFolder(GoogleApiClient apiClient) {
        if (apiClient.isConnected()) {
            return new zzw(((zzs) apiClient.zza(Drive.zzNX)).zzpC());
        }
        throw new IllegalStateException("Client must be connected");
    }

    @Override // com.google.android.gms.drive.DriveApi
    public CreateFileActivityBuilder newCreateFileActivityBuilder() {
        return new CreateFileActivityBuilder();
    }

    @Override // com.google.android.gms.drive.DriveApi
    public PendingResult<DriveApi.DriveContentsResult> newDriveContents(GoogleApiClient apiClient) {
        return zza(apiClient, DriveFile.MODE_WRITE_ONLY);
    }

    @Override // com.google.android.gms.drive.DriveApi
    public OpenFileActivityBuilder newOpenFileActivityBuilder() {
        return new OpenFileActivityBuilder();
    }

    @Override // com.google.android.gms.drive.DriveApi
    public PendingResult<DriveApi.MetadataBufferResult> query(GoogleApiClient apiClient, final Query query) {
        if (query == null) {
            throw new IllegalArgumentException("Query must be provided.");
        }
        return apiClient.zza((GoogleApiClient) new zzg(apiClient) { // from class: com.google.android.gms.drive.internal.zzq.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new QueryRequest(query), new zzi(this));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveApi
    public PendingResult<Status> requestSync(GoogleApiClient apiClient) {
        return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzq.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new zzbq(this));
            }
        });
    }

    public PendingResult<DriveApi.DriveContentsResult> zza(GoogleApiClient googleApiClient, final int i) {
        return googleApiClient.zza((GoogleApiClient) new zzb(googleApiClient) { // from class: com.google.android.gms.drive.internal.zzq.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new CreateContentsRequest(i), new zzh(this));
            }
        });
    }
}
