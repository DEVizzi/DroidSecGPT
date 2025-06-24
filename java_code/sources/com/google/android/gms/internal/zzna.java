package com.google.android.gms.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.fitness.ConfigApi;
import com.google.android.gms.fitness.request.DataTypeCreateRequest;
import com.google.android.gms.fitness.request.DataTypeReadRequest;
import com.google.android.gms.fitness.request.DisableFitRequest;
import com.google.android.gms.fitness.result.DataTypeResult;
import com.google.android.gms.internal.zzly;
import com.google.android.gms.internal.zzmh;
/* loaded from: classes.dex */
public class zzna implements ConfigApi {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends zzmh.zza {
        private final zza.zzb<DataTypeResult> zzOs;

        private zza(zza.zzb<DataTypeResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.internal.zzmh
        public void zza(DataTypeResult dataTypeResult) {
            this.zzOs.zzm(dataTypeResult);
        }
    }

    @Override // com.google.android.gms.fitness.ConfigApi
    public PendingResult<DataTypeResult> createCustomDataType(GoogleApiClient client, final DataTypeCreateRequest request) {
        return client.zzb(new zzly.zza<DataTypeResult>(client) { // from class: com.google.android.gms.internal.zzna.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzC */
            public DataTypeResult createFailedResult(Status status) {
                return DataTypeResult.zzM(status);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzly zzlyVar) throws RemoteException {
                ((zzmj) zzlyVar.zznM()).zza(new DataTypeCreateRequest(request, new zza(this), zzlyVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.ConfigApi
    public PendingResult<Status> disableFit(GoogleApiClient client) {
        return client.zzb(new zzly.zzc(client) { // from class: com.google.android.gms.internal.zzna.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzly zzlyVar) throws RemoteException {
                ((zzmj) zzlyVar.zznM()).zza(new DisableFitRequest(new zzng(this), zzlyVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.ConfigApi
    public PendingResult<DataTypeResult> readDataType(GoogleApiClient client, final String dataTypeName) {
        return client.zza((GoogleApiClient) new zzly.zza<DataTypeResult>(client) { // from class: com.google.android.gms.internal.zzna.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzC */
            public DataTypeResult createFailedResult(Status status) {
                return DataTypeResult.zzM(status);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzly zzlyVar) throws RemoteException {
                ((zzmj) zzlyVar.zznM()).zza(new DataTypeReadRequest(dataTypeName, new zza(this), zzlyVar.getContext().getPackageName()));
            }
        });
    }
}
