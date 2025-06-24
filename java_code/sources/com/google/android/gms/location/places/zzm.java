package com.google.android.gms.location.places;

import android.content.Context;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzlm;
import com.google.android.gms.location.places.internal.zzh;
/* loaded from: classes.dex */
public class zzm extends zzh.zza {
    private static final String TAG = zzm.class.getSimpleName();
    private final Context mContext;
    private final zzd zzazS;
    private final zza zzazT;
    private final zze zzazU;
    private final zzf zzazV;
    private final zzc zzazW;

    /* loaded from: classes.dex */
    public static abstract class zza<A extends Api.Client> extends zzb<AutocompletePredictionBuffer, A> {
        public zza(Api.ClientKey<A> clientKey, GoogleApiClient googleApiClient) {
            super(clientKey, googleApiClient);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaG */
        public AutocompletePredictionBuffer createFailedResult(Status status) {
            return new AutocompletePredictionBuffer(DataHolder.zzbi(status.getStatusCode()));
        }
    }

    /* loaded from: classes.dex */
    public static abstract class zzb<R extends Result, A extends Api.Client> extends zza.AbstractC0032zza<R, A> {
        public zzb(Api.ClientKey<A> clientKey, GoogleApiClient googleApiClient) {
            super(clientKey, googleApiClient);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class zzc<A extends Api.Client> extends zzb<PlaceBuffer, A> {
        public zzc(Api.ClientKey<A> clientKey, GoogleApiClient googleApiClient) {
            super(clientKey, googleApiClient);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaH */
        public PlaceBuffer createFailedResult(Status status) {
            return new PlaceBuffer(DataHolder.zzbi(status.getStatusCode()), null);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class zzd<A extends Api.Client> extends zzb<PlaceLikelihoodBuffer, A> {
        public zzd(Api.ClientKey<A> clientKey, GoogleApiClient googleApiClient) {
            super(clientKey, googleApiClient);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaI */
        public PlaceLikelihoodBuffer createFailedResult(Status status) {
            return new PlaceLikelihoodBuffer(DataHolder.zzbi(status.getStatusCode()), 100, null);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class zze<A extends Api.Client> extends zzb<com.google.android.gms.location.places.personalized.zzd, A> {
        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaJ */
        public com.google.android.gms.location.places.personalized.zzd createFailedResult(Status status) {
            return com.google.android.gms.location.places.personalized.zzd.zzaK(status);
        }
    }

    /* loaded from: classes.dex */
    public static abstract class zzf<A extends Api.Client> extends zzb<Status, A> {
        public zzf(Api.ClientKey<A> clientKey, GoogleApiClient googleApiClient) {
            super(clientKey, googleApiClient);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            return status;
        }
    }

    public zzm(zza zzaVar) {
        this.zzazS = null;
        this.zzazT = zzaVar;
        this.zzazU = null;
        this.zzazV = null;
        this.zzazW = null;
        this.mContext = null;
    }

    public zzm(zzc zzcVar, Context context) {
        this.zzazS = null;
        this.zzazT = null;
        this.zzazU = null;
        this.zzazV = null;
        this.zzazW = zzcVar;
        this.mContext = context;
    }

    public zzm(zzd zzdVar, Context context) {
        this.zzazS = zzdVar;
        this.zzazT = null;
        this.zzazU = null;
        this.zzazV = null;
        this.zzazW = null;
        this.mContext = context;
    }

    public zzm(zzf zzfVar) {
        this.zzazS = null;
        this.zzazT = null;
        this.zzazU = null;
        this.zzazV = zzfVar;
        this.zzazW = null;
        this.mContext = null;
    }

    @Override // com.google.android.gms.location.places.internal.zzh
    public void zzY(DataHolder dataHolder) throws RemoteException {
        zzu.zza(this.zzazS != null, "placeEstimator cannot be null");
        if (dataHolder != null) {
            this.zzazS.setResult(new PlaceLikelihoodBuffer(dataHolder, 100, this.mContext));
            return;
        }
        if (Log.isLoggable(TAG, 6)) {
            Log.e(TAG, "onPlaceEstimated received null DataHolder: " + zzlm.zzpa());
        }
        this.zzazS.zzr(Status.zzXR);
    }

    @Override // com.google.android.gms.location.places.internal.zzh
    public void zzZ(DataHolder dataHolder) throws RemoteException {
        if (dataHolder != null) {
            this.zzazT.setResult(new AutocompletePredictionBuffer(dataHolder));
            return;
        }
        if (Log.isLoggable(TAG, 6)) {
            Log.e(TAG, "onAutocompletePrediction received null DataHolder: " + zzlm.zzpa());
        }
        this.zzazT.zzr(Status.zzXR);
    }

    @Override // com.google.android.gms.location.places.internal.zzh
    public void zzaF(Status status) throws RemoteException {
        this.zzazV.setResult(status);
    }

    @Override // com.google.android.gms.location.places.internal.zzh
    public void zzaa(DataHolder dataHolder) throws RemoteException {
        if (dataHolder != null) {
            this.zzazU.setResult(new com.google.android.gms.location.places.personalized.zzd(dataHolder));
            return;
        }
        if (Log.isLoggable(TAG, 6)) {
            Log.e(TAG, "onPlaceUserDataFetched received null DataHolder: " + zzlm.zzpa());
        }
        this.zzazU.zzr(Status.zzXR);
    }

    @Override // com.google.android.gms.location.places.internal.zzh
    public void zzab(DataHolder dataHolder) throws RemoteException {
        this.zzazW.setResult(new PlaceBuffer(dataHolder, this.mContext));
    }
}
