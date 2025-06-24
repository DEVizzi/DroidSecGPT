package com.google.android.gms.internal;

import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.fitness.HistoryApi;
import com.google.android.gms.fitness.data.DataSet;
import com.google.android.gms.fitness.data.DataType;
import com.google.android.gms.fitness.request.DailyTotalRequest;
import com.google.android.gms.fitness.request.DataDeleteRequest;
import com.google.android.gms.fitness.request.DataInsertRequest;
import com.google.android.gms.fitness.request.DataReadRequest;
import com.google.android.gms.fitness.result.DailyTotalResult;
import com.google.android.gms.fitness.result.DataReadResult;
import com.google.android.gms.internal.zzlz;
import com.google.android.gms.internal.zzme;
import com.google.android.gms.internal.zzmf;
/* loaded from: classes.dex */
public class zznb implements HistoryApi {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends zzmf.zza {
        private final zza.zzb<DataReadResult> zzOs;
        private int zzalm;
        private DataReadResult zzaln;

        private zza(zza.zzb<DataReadResult> zzbVar) {
            this.zzalm = 0;
            this.zzaln = null;
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.internal.zzmf
        public void zza(DataReadResult dataReadResult) {
            synchronized (this) {
                Log.v("Fitness", "Received batch result");
                if (this.zzaln == null) {
                    this.zzaln = dataReadResult;
                } else {
                    this.zzaln.zzb(dataReadResult);
                }
                this.zzalm++;
                if (this.zzalm == this.zzaln.zzrt()) {
                    this.zzOs.zzm(this.zzaln);
                }
            }
        }
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, final DataSet dataSet, final boolean z) {
        com.google.android.gms.common.internal.zzu.zzb(dataSet, "Must set the data set");
        com.google.android.gms.common.internal.zzu.zza(!dataSet.getDataPoints().isEmpty(), "Cannot use an empty data set");
        com.google.android.gms.common.internal.zzu.zzb(dataSet.getDataSource().zzqB(), "Must set the app package name for the data source");
        return googleApiClient.zza((GoogleApiClient) new zzlz.zzc(googleApiClient) { // from class: com.google.android.gms.internal.zznb.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlz zzlzVar) throws RemoteException {
                ((zzmk) zzlzVar.zznM()).zza(new DataInsertRequest(dataSet, new zzng(this), zzlzVar.getContext().getPackageName(), z));
            }
        });
    }

    @Override // com.google.android.gms.fitness.HistoryApi
    public PendingResult<Status> deleteData(GoogleApiClient client, final DataDeleteRequest request) {
        return client.zza((GoogleApiClient) new zzlz.zzc(client) { // from class: com.google.android.gms.internal.zznb.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlz zzlzVar) throws RemoteException {
                ((zzmk) zzlzVar.zznM()).zza(new DataDeleteRequest(request, new zzng(this), zzlzVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.HistoryApi
    public PendingResult<Status> insertData(GoogleApiClient client, DataSet dataSet) {
        return zza(client, dataSet, false);
    }

    @Override // com.google.android.gms.fitness.HistoryApi
    public PendingResult<DailyTotalResult> readDailyTotal(GoogleApiClient client, final DataType dataType) {
        return client.zza((GoogleApiClient) new zzlz.zza<DailyTotalResult>(client) { // from class: com.google.android.gms.internal.zznb.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzE */
            public DailyTotalResult createFailedResult(Status status) {
                return DailyTotalResult.zzK(status);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlz zzlzVar) throws RemoteException {
                ((zzmk) zzlzVar.zznM()).zza(new DailyTotalRequest(new zzme.zza() { // from class: com.google.android.gms.internal.zznb.4.1
                    @Override // com.google.android.gms.internal.zzme
                    public void zza(DailyTotalResult dailyTotalResult) throws RemoteException {
                        setResult(dailyTotalResult);
                    }
                }, dataType, zzlzVar.getContext().getPackageName()));
            }
        });
    }

    @Override // com.google.android.gms.fitness.HistoryApi
    public PendingResult<DataReadResult> readData(GoogleApiClient client, final DataReadRequest request) {
        return client.zza((GoogleApiClient) new zzlz.zza<DataReadResult>(client) { // from class: com.google.android.gms.internal.zznb.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzD */
            public DataReadResult createFailedResult(Status status) {
                return DataReadResult.zza(status, request);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzlz zzlzVar) throws RemoteException {
                ((zzmk) zzlzVar.zznM()).zza(new DataReadRequest(request, new zza(this), zzlzVar.getContext().getPackageName()));
            }
        });
    }
}
