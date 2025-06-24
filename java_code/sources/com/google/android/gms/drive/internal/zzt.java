package com.google.android.gms.drive.internal;

import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.ResultCallback;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.drive.Contents;
import com.google.android.gms.drive.DriveApi;
import com.google.android.gms.drive.DriveContents;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.ExecutionOptions;
import com.google.android.gms.drive.MetadataChangeSet;
import com.google.android.gms.drive.internal.zzq;
import com.google.android.gms.drive.internal.zzr;
import com.google.android.gms.internal.zzlg;
import java.io.InputStream;
import java.io.OutputStream;
/* loaded from: classes.dex */
public class zzt implements DriveContents {
    private final Contents zzafa;
    private boolean mClosed = false;
    private boolean zzafb = false;
    private boolean zzafc = false;

    public zzt(Contents contents) {
        this.zzafa = (Contents) com.google.android.gms.common.internal.zzu.zzu(contents);
    }

    @Override // com.google.android.gms.drive.DriveContents
    public PendingResult<Status> commit(GoogleApiClient apiClient, MetadataChangeSet changeSet) {
        return commit(apiClient, changeSet, null);
    }

    @Override // com.google.android.gms.drive.DriveContents
    public PendingResult<Status> commit(GoogleApiClient apiClient, final MetadataChangeSet changeSet, final ExecutionOptions executionOptions) {
        if (executionOptions == null) {
            executionOptions = new ExecutionOptions.Builder().build();
        }
        if (this.zzafa.getMode() == 268435456) {
            throw new IllegalStateException("Cannot commit contents opened with MODE_READ_ONLY");
        }
        if (!ExecutionOptions.zzbX(executionOptions.zzpk()) || this.zzafa.zzpc()) {
            ExecutionOptions.zza(apiClient, executionOptions);
            if (zzpg()) {
                throw new IllegalStateException("DriveContents already closed.");
            }
            if (getDriveId() == null) {
                throw new IllegalStateException("Only DriveContents obtained through DriveFile.open can be committed.");
            }
            if (changeSet == null) {
                changeSet = MetadataChangeSet.zzads;
            }
            zzpf();
            return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzt.2
                /* JADX INFO: Access modifiers changed from: protected */
                @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
                public void zza(zzs zzsVar) throws RemoteException {
                    changeSet.zzpm().setContext(zzsVar.getContext());
                    zzsVar.zzpB().zza(new CloseContentsAndUpdateMetadataRequest(zzt.this.zzafa.getDriveId(), changeSet.zzpm(), zzt.this.zzafa.getRequestId(), zzt.this.zzafa.zzpc(), executionOptions), new zzbq(this));
                }
            });
        }
        throw new IllegalStateException("DriveContents must be valid for conflict detection.");
    }

    @Override // com.google.android.gms.drive.DriveContents
    public void discard(GoogleApiClient apiClient) {
        if (zzpg()) {
            throw new IllegalStateException("DriveContents already closed.");
        }
        zzpf();
        ((AnonymousClass4) apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzt.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new CloseContentsRequest(zzt.this.zzafa.getRequestId(), false), new zzbq(this));
            }
        })).setResultCallback(new ResultCallback<Status>() { // from class: com.google.android.gms.drive.internal.zzt.3
            @Override // com.google.android.gms.common.api.ResultCallback
            /* renamed from: zzm */
            public void onResult(Status status) {
                if (status.isSuccess()) {
                    zzx.zzt("DriveContentsImpl", "Contents discarded");
                } else {
                    zzx.zzv("DriveContentsImpl", "Error discarding contents");
                }
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveContents
    public DriveId getDriveId() {
        return this.zzafa.getDriveId();
    }

    @Override // com.google.android.gms.drive.DriveContents
    public InputStream getInputStream() {
        if (zzpg()) {
            throw new IllegalStateException("Contents have been closed, cannot access the input stream.");
        }
        if (this.zzafa.getMode() != 268435456) {
            throw new IllegalStateException("getInputStream() can only be used with contents opened with MODE_READ_ONLY.");
        }
        if (this.zzafb) {
            throw new IllegalStateException("getInputStream() can only be called once per Contents instance.");
        }
        this.zzafb = true;
        return this.zzafa.getInputStream();
    }

    @Override // com.google.android.gms.drive.DriveContents
    public int getMode() {
        return this.zzafa.getMode();
    }

    @Override // com.google.android.gms.drive.DriveContents
    public OutputStream getOutputStream() {
        if (zzpg()) {
            throw new IllegalStateException("Contents have been closed, cannot access the output stream.");
        }
        if (this.zzafa.getMode() != 536870912) {
            throw new IllegalStateException("getOutputStream() can only be used with contents opened with MODE_WRITE_ONLY.");
        }
        if (this.zzafc) {
            throw new IllegalStateException("getOutputStream() can only be called once per Contents instance.");
        }
        this.zzafc = true;
        return this.zzafa.getOutputStream();
    }

    @Override // com.google.android.gms.drive.DriveContents
    public ParcelFileDescriptor getParcelFileDescriptor() {
        if (zzpg()) {
            throw new IllegalStateException("Contents have been closed, cannot access the output stream.");
        }
        return this.zzafa.getParcelFileDescriptor();
    }

    @Override // com.google.android.gms.drive.DriveContents
    public PendingResult<DriveApi.DriveContentsResult> reopenForWrite(GoogleApiClient apiClient) {
        if (zzpg()) {
            throw new IllegalStateException("DriveContents already closed.");
        }
        if (this.zzafa.getMode() != 268435456) {
            throw new IllegalStateException("reopenForWrite can only be used with DriveContents opened with MODE_READ_ONLY.");
        }
        zzpf();
        return apiClient.zza((GoogleApiClient) new zzq.zzb(apiClient) { // from class: com.google.android.gms.drive.internal.zzt.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new OpenContentsRequest(zzt.this.getDriveId(), DriveFile.MODE_WRITE_ONLY, zzt.this.zzafa.getRequestId()), new zzbi(this, null));
            }
        });
    }

    @Override // com.google.android.gms.drive.DriveContents
    public Contents zzpe() {
        return this.zzafa;
    }

    @Override // com.google.android.gms.drive.DriveContents
    public void zzpf() {
        zzlg.zza(this.zzafa.getParcelFileDescriptor());
        this.mClosed = true;
    }

    @Override // com.google.android.gms.drive.DriveContents
    public boolean zzpg() {
        return this.mClosed;
    }
}
