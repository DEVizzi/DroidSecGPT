package com.google.android.gms.wearable.internal;

import android.content.IntentFilter;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.wearable.Asset;
import com.google.android.gms.wearable.DataApi;
import com.google.android.gms.wearable.DataItem;
import com.google.android.gms.wearable.DataItemAsset;
import com.google.android.gms.wearable.DataItemBuffer;
import com.google.android.gms.wearable.PutDataRequest;
import java.io.IOException;
import java.io.InputStream;
/* loaded from: classes.dex */
public final class zzu implements DataApi {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zza extends zzf<Status> {
        private DataApi.DataListener zzaUj;
        private IntentFilter[] zzaUk;

        private zza(GoogleApiClient googleApiClient, DataApi.DataListener dataListener, IntentFilter[] intentFilterArr) {
            super(googleApiClient);
            this.zzaUj = dataListener;
            this.zzaUk = intentFilterArr;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public void zza(zzbk zzbkVar) throws RemoteException {
            zzbkVar.zza(this, this.zzaUj, this.zzaUk);
            this.zzaUj = null;
            this.zzaUk = null;
        }

        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            this.zzaUj = null;
            this.zzaUk = null;
            return status;
        }
    }

    /* loaded from: classes.dex */
    public static class zzb implements DataApi.DataItemResult {
        private final Status zzOt;
        private final DataItem zzaUl;

        public zzb(Status status, DataItem dataItem) {
            this.zzOt = status;
            this.zzaUl = dataItem;
        }

        @Override // com.google.android.gms.wearable.DataApi.DataItemResult
        public DataItem getDataItem() {
            return this.zzaUl;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    public static class zzc implements DataApi.DeleteDataItemsResult {
        private final Status zzOt;
        private final int zzaUm;

        public zzc(Status status, int i) {
            this.zzOt = status;
            this.zzaUm = i;
        }

        @Override // com.google.android.gms.wearable.DataApi.DeleteDataItemsResult
        public int getNumDeleted() {
            return this.zzaUm;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* loaded from: classes.dex */
    public static class zzd implements DataApi.GetFdForAssetResult {
        private volatile boolean mClosed = false;
        private final Status zzOt;
        private volatile InputStream zzaTV;
        private volatile ParcelFileDescriptor zzaUn;

        public zzd(Status status, ParcelFileDescriptor parcelFileDescriptor) {
            this.zzOt = status;
            this.zzaUn = parcelFileDescriptor;
        }

        @Override // com.google.android.gms.wearable.DataApi.GetFdForAssetResult
        public ParcelFileDescriptor getFd() {
            if (this.mClosed) {
                throw new IllegalStateException("Cannot access the file descriptor after release().");
            }
            return this.zzaUn;
        }

        @Override // com.google.android.gms.wearable.DataApi.GetFdForAssetResult
        public InputStream getInputStream() {
            if (this.mClosed) {
                throw new IllegalStateException("Cannot access the input stream after release().");
            }
            if (this.zzaUn == null) {
                return null;
            }
            if (this.zzaTV == null) {
                this.zzaTV = new ParcelFileDescriptor.AutoCloseInputStream(this.zzaUn);
            }
            return this.zzaTV;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzaUn == null) {
                return;
            }
            if (this.mClosed) {
                throw new IllegalStateException("releasing an already released result.");
            }
            try {
                if (this.zzaTV != null) {
                    this.zzaTV.close();
                } else {
                    this.zzaUn.close();
                }
                this.mClosed = true;
                this.zzaUn = null;
                this.zzaTV = null;
            } catch (IOException e) {
            }
        }
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, DataApi.DataListener dataListener, IntentFilter[] intentFilterArr) {
        return googleApiClient.zza((GoogleApiClient) new zza(googleApiClient, dataListener, intentFilterArr));
    }

    private void zza(Asset asset) {
        if (asset == null) {
            throw new IllegalArgumentException("asset is null");
        }
        if (asset.getDigest() == null) {
            throw new IllegalArgumentException("invalid asset");
        }
        if (asset.getData() != null) {
            throw new IllegalArgumentException("invalid asset");
        }
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<Status> addListener(GoogleApiClient client, DataApi.DataListener listener) {
        return zza(client, listener, null);
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataApi.DeleteDataItemsResult> deleteDataItems(GoogleApiClient client, Uri uri) {
        return deleteDataItems(client, uri, 0);
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataApi.DeleteDataItemsResult> deleteDataItems(GoogleApiClient client, final Uri uri, final int filterType) {
        return client.zza((GoogleApiClient) new zzf<DataApi.DeleteDataItemsResult>(client) { // from class: com.google.android.gms.wearable.internal.zzu.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzb(this, uri, filterType);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbf */
            public DataApi.DeleteDataItemsResult createFailedResult(Status status) {
                return new zzc(status, 0);
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataApi.DataItemResult> getDataItem(GoogleApiClient client, final Uri uri) {
        return client.zza((GoogleApiClient) new zzf<DataApi.DataItemResult>(client) { // from class: com.google.android.gms.wearable.internal.zzu.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, uri);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbd */
            public DataApi.DataItemResult createFailedResult(Status status) {
                return new zzb(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataItemBuffer> getDataItems(GoogleApiClient client) {
        return client.zza((GoogleApiClient) new zzf<DataItemBuffer>(client) { // from class: com.google.android.gms.wearable.internal.zzu.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zzl(this);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbe */
            public DataItemBuffer createFailedResult(Status status) {
                return new DataItemBuffer(DataHolder.zzbi(status.getStatusCode()));
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataItemBuffer> getDataItems(GoogleApiClient client, Uri uri) {
        return getDataItems(client, uri, 0);
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataItemBuffer> getDataItems(GoogleApiClient client, final Uri uri, final int filterType) {
        return client.zza((GoogleApiClient) new zzf<DataItemBuffer>(client) { // from class: com.google.android.gms.wearable.internal.zzu.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, uri, filterType);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbe */
            public DataItemBuffer createFailedResult(Status status) {
                return new DataItemBuffer(DataHolder.zzbi(status.getStatusCode()));
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataApi.GetFdForAssetResult> getFdForAsset(GoogleApiClient client, final Asset asset) {
        zza(asset);
        return client.zza((GoogleApiClient) new zzf<DataApi.GetFdForAssetResult>(client) { // from class: com.google.android.gms.wearable.internal.zzu.6
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, asset);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbg */
            public DataApi.GetFdForAssetResult createFailedResult(Status status) {
                return new zzd(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataApi.GetFdForAssetResult> getFdForAsset(GoogleApiClient client, final DataItemAsset asset) {
        return client.zza((GoogleApiClient) new zzf<DataApi.GetFdForAssetResult>(client) { // from class: com.google.android.gms.wearable.internal.zzu.7
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, asset);
            }

            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbg */
            public DataApi.GetFdForAssetResult createFailedResult(Status status) {
                return new zzd(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<DataApi.DataItemResult> putDataItem(GoogleApiClient client, final PutDataRequest request) {
        return client.zza((GoogleApiClient) new zzf<DataApi.DataItemResult>(client) { // from class: com.google.android.gms.wearable.internal.zzu.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, request);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzbd */
            public DataApi.DataItemResult createFailedResult(Status status) {
                return new zzb(status, null);
            }
        });
    }

    @Override // com.google.android.gms.wearable.DataApi
    public PendingResult<Status> removeListener(GoogleApiClient client, final DataApi.DataListener listener) {
        return client.zza((GoogleApiClient) new zzf<Status>(client) { // from class: com.google.android.gms.wearable.internal.zzu.8
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzbk zzbkVar) throws RemoteException {
                zzbkVar.zza(this, listener);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzb */
            public Status createFailedResult(Status status) {
                return status;
            }
        });
    }
}
