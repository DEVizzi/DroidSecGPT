package com.google.android.gms.internal;

import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.internal.zzpm;
import com.google.android.gms.search.GoogleNowAuthState;
import com.google.android.gms.search.SearchAuth;
import com.google.android.gms.search.SearchAuthApi;
/* loaded from: classes.dex */
public class zzpp implements SearchAuthApi {

    /* loaded from: classes.dex */
    static abstract class zza extends zzpm.zza {
        zza() {
        }

        @Override // com.google.android.gms.internal.zzpm
        public void zza(Status status, GoogleNowAuthState googleNowAuthState) {
            throw new UnsupportedOperationException();
        }
    }

    /* loaded from: classes.dex */
    static class zzb extends zza.AbstractC0032zza<SearchAuthApi.GoogleNowAuthResult, zzpo> {
        private final GoogleApiClient zzRa;
        private final String zzaJI;
        private final boolean zzaJJ;

        protected zzb(GoogleApiClient googleApiClient, String str) {
            super(SearchAuth.zzNX, googleApiClient);
            this.zzaJJ = Log.isLoggable("SearchAuth", 3);
            this.zzRa = googleApiClient;
            this.zzaJI = str;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzpo zzpoVar) throws RemoteException {
            if (this.zzaJJ) {
                Log.d("SearchAuth", "GetGoogleNowAuthImpl started");
            }
            String packageName = this.zzRa.getContext().getPackageName();
            zzpoVar.zznM().zza(new zza() { // from class: com.google.android.gms.internal.zzpp.zzb.1
                @Override // com.google.android.gms.internal.zzpp.zza, com.google.android.gms.internal.zzpm
                public void zza(Status status, GoogleNowAuthState googleNowAuthState) {
                    if (zzb.this.zzaJJ) {
                        Log.d("SearchAuth", "GetGoogleNowAuthImpl success");
                    }
                    zzb.this.setResult(new zzc(status, googleNowAuthState));
                }
            }, packageName, this.zzaJI);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaS */
        public SearchAuthApi.GoogleNowAuthResult createFailedResult(Status status) {
            if (this.zzaJJ) {
                Log.d("SearchAuth", "GetGoogleNowAuthImpl received failure: " + status.getStatusMessage());
            }
            return new zzc(status, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zzc implements SearchAuthApi.GoogleNowAuthResult {
        private final Status zzOt;
        private final GoogleNowAuthState zzaJL;

        zzc(Status status, GoogleNowAuthState googleNowAuthState) {
            this.zzOt = status;
            this.zzaJL = googleNowAuthState;
        }

        @Override // com.google.android.gms.search.SearchAuthApi.GoogleNowAuthResult
        public GoogleNowAuthState getGoogleNowAuthState() {
            return this.zzaJL;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    @Override // com.google.android.gms.search.SearchAuthApi
    public PendingResult<SearchAuthApi.GoogleNowAuthResult> getGoogleNowAuth(GoogleApiClient client, String webAppClientId) {
        return client.zza((GoogleApiClient) new zzb(client, webAppClientId));
    }
}
