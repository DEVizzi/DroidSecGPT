package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.android.gms.appinvite.AppInvite;
import com.google.android.gms.appinvite.AppInviteApi;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.internal.zziy;
/* loaded from: classes.dex */
public class zziw implements AppInviteApi {

    /* loaded from: classes.dex */
    static abstract class zza<R extends Result> extends zza.AbstractC0032zza<R, zzix> {
        public zza(GoogleApiClient googleApiClient) {
            super(AppInvite.zzNX, googleApiClient);
        }
    }

    /* loaded from: classes.dex */
    final class zzb extends zza<Status> {
        private final String zzNZ;

        public zzb(GoogleApiClient googleApiClient, String str) {
            super(googleApiClient);
            this.zzNZ = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzix zzixVar) throws RemoteException {
            zzixVar.zzb(new zziy.zza() { // from class: com.google.android.gms.internal.zziw.zzb.1
                @Override // com.google.android.gms.internal.zziy
                public void zzc(Status status) throws RemoteException {
                    zzb.this.setResult(status);
                }
            }, this.zzNZ);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            return status;
        }
    }

    /* loaded from: classes.dex */
    final class zzc extends zza<Status> {
        private final String zzNZ;

        public zzc(GoogleApiClient googleApiClient, String str) {
            super(googleApiClient);
            this.zzNZ = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzix zzixVar) throws RemoteException {
            zzixVar.zza(new zziy.zza() { // from class: com.google.android.gms.internal.zziw.zzc.1
                @Override // com.google.android.gms.internal.zziy
                public void zzc(Status status) throws RemoteException {
                    zzc.this.setResult(status);
                }
            }, this.zzNZ);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            return status;
        }
    }

    @Override // com.google.android.gms.appinvite.AppInviteApi
    public PendingResult<Status> convertInvitation(GoogleApiClient client, String invitationId) {
        return client.zza((GoogleApiClient) new zzc(client, invitationId));
    }

    @Override // com.google.android.gms.appinvite.AppInviteApi
    public PendingResult<Status> updateInvitationOnInstall(GoogleApiClient client, String invitationId) {
        return client.zza((GoogleApiClient) new zzb(client, invitationId));
    }
}
