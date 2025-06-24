package com.google.android.gms.drive.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.drive.DriveApi;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.drive.internal.zzq;
/* loaded from: classes.dex */
class zzbi extends zzd {
    private final zza.zzb<DriveApi.DriveContentsResult> zzOs;
    private final DriveFile.DownloadProgressListener zzags;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzbi(zza.zzb<DriveApi.DriveContentsResult> zzbVar, DriveFile.DownloadProgressListener downloadProgressListener) {
        this.zzOs = zzbVar;
        this.zzags = downloadProgressListener;
    }

    @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
    public void zza(OnContentsResponse onContentsResponse) throws RemoteException {
        this.zzOs.zzm(new zzq.zza(onContentsResponse.zzpK() ? new Status(-1) : Status.zzXP, new zzt(onContentsResponse.zzpJ())));
    }

    @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
    public void zza(OnDownloadProgressResponse onDownloadProgressResponse) throws RemoteException {
        if (this.zzags != null) {
            this.zzags.onProgress(onDownloadProgressResponse.zzpM(), onDownloadProgressResponse.zzpN());
        }
    }

    @Override // com.google.android.gms.drive.internal.zzd, com.google.android.gms.drive.internal.zzal
    public void zzt(Status status) throws RemoteException {
        this.zzOs.zzm(new zzq.zza(status, null));
    }
}
