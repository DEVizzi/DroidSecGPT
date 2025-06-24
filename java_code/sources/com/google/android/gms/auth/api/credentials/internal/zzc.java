package com.google.android.gms.auth.api.credentials.internal;

import android.content.Context;
import android.os.RemoteException;
import com.google.android.gms.auth.api.credentials.Credential;
import com.google.android.gms.auth.api.credentials.CredentialRequest;
import com.google.android.gms.auth.api.credentials.CredentialRequestResult;
import com.google.android.gms.auth.api.credentials.CredentialsApi;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
/* loaded from: classes.dex */
public final class zzc implements CredentialsApi {

    /* loaded from: classes.dex */
    private static class zza extends com.google.android.gms.auth.api.credentials.internal.zza {
        private zza.zzb<Status> zzPg;

        zza(zza.zzb<Status> zzbVar) {
            this.zzPg = zzbVar;
        }

        @Override // com.google.android.gms.auth.api.credentials.internal.zza, com.google.android.gms.auth.api.credentials.internal.ICredentialsCallbacks
        public void onStatusResult(Status status) {
            this.zzPg.zzm(status);
        }
    }

    @Override // com.google.android.gms.auth.api.credentials.CredentialsApi
    public PendingResult<Status> delete(GoogleApiClient client, final Credential credential) {
        return client.zzb(new zzd<Status>(client) { // from class: com.google.android.gms.auth.api.credentials.internal.zzc.3
            @Override // com.google.android.gms.auth.api.credentials.internal.zzd
            protected void zza(Context context, ICredentialsService iCredentialsService) throws RemoteException {
                iCredentialsService.performCredentialsDeleteOperation(new zza(this), new DeleteRequest(credential));
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    @Override // com.google.android.gms.auth.api.credentials.CredentialsApi
    public PendingResult<Status> disableAutoSignIn(GoogleApiClient client) {
        return client.zzb(new zzd<Status>(client) { // from class: com.google.android.gms.auth.api.credentials.internal.zzc.4
            @Override // com.google.android.gms.auth.api.credentials.internal.zzd
            protected void zza(Context context, ICredentialsService iCredentialsService) throws RemoteException {
                iCredentialsService.performDisableAutoSignInOperation(new zza(this));
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }

    @Override // com.google.android.gms.auth.api.credentials.CredentialsApi
    public PendingResult<CredentialRequestResult> request(GoogleApiClient client, final CredentialRequest request) {
        return client.zza((GoogleApiClient) new zzd<CredentialRequestResult>(client) { // from class: com.google.android.gms.auth.api.credentials.internal.zzc.1
            @Override // com.google.android.gms.auth.api.credentials.internal.zzd
            protected void zza(Context context, ICredentialsService iCredentialsService) throws RemoteException {
                iCredentialsService.performCredentialsRequestOperation(new com.google.android.gms.auth.api.credentials.internal.zza() { // from class: com.google.android.gms.auth.api.credentials.internal.zzc.1.1
                    @Override // com.google.android.gms.auth.api.credentials.internal.zza, com.google.android.gms.auth.api.credentials.internal.ICredentialsCallbacks
                    public void onCredentialResult(Status status, Credential credential) {
                        setResult(new zzb(status, credential));
                    }
                }, request);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzk */
            public CredentialRequestResult createFailedResult(Status status) {
                return zzb.zzj(status);
            }
        });
    }

    @Override // com.google.android.gms.auth.api.credentials.CredentialsApi
    public PendingResult<Status> save(GoogleApiClient client, final Credential credential) {
        return client.zzb(new zzd<Status>(client) { // from class: com.google.android.gms.auth.api.credentials.internal.zzc.2
            @Override // com.google.android.gms.auth.api.credentials.internal.zzd
            protected void zza(Context context, ICredentialsService iCredentialsService) throws RemoteException {
                iCredentialsService.performCredentialsSaveOperation(new zza(this), new SaveRequest(credential));
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }
}
