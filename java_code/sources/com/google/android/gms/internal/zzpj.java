package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.safetynet.AttestationData;
import com.google.android.gms.safetynet.SafetyNetApi;
/* loaded from: classes.dex */
public class zzpj implements SafetyNetApi {

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zza implements SafetyNetApi.AttestationResult {
        private final Status zzOt;
        private final AttestationData zzaJB;

        public zza(Status status, AttestationData attestationData) {
            this.zzOt = status;
            this.zzaJB = attestationData;
        }

        @Override // com.google.android.gms.safetynet.SafetyNetApi.AttestationResult
        public String getJwsResult() {
            if (this.zzaJB == null) {
                return null;
            }
            return this.zzaJB.getJwsResult();
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static abstract class zzb extends zzpg<SafetyNetApi.AttestationResult> {
        protected zzph zzaJC;

        public zzb(GoogleApiClient googleApiClient) {
            super(googleApiClient);
            this.zzaJC = new zzpf() { // from class: com.google.android.gms.internal.zzpj.zzb.1
                @Override // com.google.android.gms.internal.zzpf, com.google.android.gms.internal.zzph
                public void zza(Status status, AttestationData attestationData) {
                    zzb.this.setResult(new zza(status, attestationData));
                }
            };
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaR */
        public SafetyNetApi.AttestationResult createFailedResult(Status status) {
            return new zza(status, null);
        }
    }

    @Override // com.google.android.gms.safetynet.SafetyNetApi
    public PendingResult<SafetyNetApi.AttestationResult> attest(GoogleApiClient googleApiClient, final byte[] nonce) {
        return googleApiClient.zza((GoogleApiClient) new zzb(googleApiClient) { // from class: com.google.android.gms.internal.zzpj.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzpk zzpkVar) throws RemoteException {
                zzpkVar.zza(this.zzaJC, nonce);
            }
        });
    }
}
