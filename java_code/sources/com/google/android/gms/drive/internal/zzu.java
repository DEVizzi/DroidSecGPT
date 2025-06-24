package com.google.android.gms.drive.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.zzi;
import com.google.android.gms.drive.DriveApi;
import com.google.android.gms.drive.DriveFile;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.internal.zzq;
/* loaded from: classes.dex */
public class zzu extends zzz implements DriveFile {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza implements DriveFile.DownloadProgressListener {
        private final com.google.android.gms.common.api.zzi<DriveFile.DownloadProgressListener> zzafi;

        public zza(com.google.android.gms.common.api.zzi<DriveFile.DownloadProgressListener> zziVar) {
            this.zzafi = zziVar;
        }

        @Override // com.google.android.gms.drive.DriveFile.DownloadProgressListener
        public void onProgress(final long bytesDownloaded, final long bytesExpected) {
            this.zzafi.zza(new zzi.zzb<DriveFile.DownloadProgressListener>() { // from class: com.google.android.gms.drive.internal.zzu.zza.1
                @Override // com.google.android.gms.common.api.zzi.zzb
                /* renamed from: zza */
                public void zzn(DriveFile.DownloadProgressListener downloadProgressListener) {
                    downloadProgressListener.onProgress(bytesDownloaded, bytesExpected);
                }

                @Override // com.google.android.gms.common.api.zzi.zzb
                public void zzmw() {
                }
            });
        }
    }

    public zzu(DriveId driveId) {
        super(driveId);
    }

    private static DriveFile.DownloadProgressListener zza(GoogleApiClient googleApiClient, DriveFile.DownloadProgressListener downloadProgressListener) {
        if (downloadProgressListener == null) {
            return null;
        }
        return new zza(googleApiClient.zzo(downloadProgressListener));
    }

    @Override // com.google.android.gms.drive.DriveFile
    public PendingResult<DriveApi.DriveContentsResult> open(GoogleApiClient apiClient, final int mode, DriveFile.DownloadProgressListener listener) {
        if (mode == 268435456 || mode == 536870912 || mode == 805306368) {
            final DriveFile.DownloadProgressListener zza2 = zza(apiClient, listener);
            return apiClient.zza((GoogleApiClient) new zzq.zzb(apiClient) { // from class: com.google.android.gms.drive.internal.zzu.1
                /* JADX INFO: Access modifiers changed from: protected */
                @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
                public void zza(zzs zzsVar) throws RemoteException {
                    setCancelToken(zzsVar.zzpB().zza(new OpenContentsRequest(zzu.this.getDriveId(), mode, 0), new zzbi(this, zza2)).zzpF());
                }
            });
        }
        throw new IllegalArgumentException("Invalid mode provided.");
    }
}
