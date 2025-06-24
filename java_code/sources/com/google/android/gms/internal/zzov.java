package com.google.android.gms.internal;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.internal.zzot;
import com.google.android.gms.panorama.Panorama;
import com.google.android.gms.panorama.PanoramaApi;
/* loaded from: classes.dex */
public class zzov implements PanoramaApi {

    /* loaded from: classes.dex */
    private static abstract class zza extends zzc<PanoramaApi.PanoramaResult> {
        public zza(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzaN */
        public PanoramaApi.PanoramaResult createFailedResult(Status status) {
            return new zzox(status, null);
        }
    }

    /* loaded from: classes.dex */
    private static final class zzb extends zzot.zza {
        private final zza.zzb<PanoramaApi.PanoramaResult> zzOs;

        public zzb(zza.zzb<PanoramaApi.PanoramaResult> zzbVar) {
            this.zzOs = zzbVar;
        }

        @Override // com.google.android.gms.internal.zzot
        public void zza(int i, Bundle bundle, int i2, Intent intent) {
            this.zzOs.zzm(new zzox(new Status(i, null, bundle != null ? (PendingIntent) bundle.getParcelable("pendingIntent") : null), intent));
        }
    }

    /* loaded from: classes.dex */
    private static abstract class zzc<R extends Result> extends zza.AbstractC0032zza<R, zzow> {
        protected zzc(GoogleApiClient googleApiClient) {
            super(Panorama.zzNX, googleApiClient);
        }

        protected abstract void zza(Context context, zzou zzouVar) throws RemoteException;

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
        public final void zza(zzow zzowVar) throws RemoteException {
            zza(zzowVar.getContext(), zzowVar.zznM());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zza(Context context, Uri uri) {
        context.revokeUriPermission(uri, 1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void zza(final Context context, zzou zzouVar, final zzot zzotVar, final Uri uri, Bundle bundle) throws RemoteException {
        context.grantUriPermission("com.google.android.gms", uri, 1);
        try {
            zzouVar.zza(new zzot.zza() { // from class: com.google.android.gms.internal.zzov.3
                @Override // com.google.android.gms.internal.zzot
                public void zza(int i, Bundle bundle2, int i2, Intent intent) throws RemoteException {
                    zzov.zza(context, uri);
                    zzotVar.zza(i, bundle2, i2, intent);
                }
            }, uri, bundle, true);
        } catch (RemoteException e) {
            zza(context, uri);
            throw e;
        } catch (RuntimeException e2) {
            zza(context, uri);
            throw e2;
        }
    }

    @Override // com.google.android.gms.panorama.PanoramaApi
    public PendingResult<PanoramaApi.PanoramaResult> loadPanoramaInfo(GoogleApiClient client, final Uri uri) {
        return client.zza((GoogleApiClient) new zza(client) { // from class: com.google.android.gms.internal.zzov.1
            @Override // com.google.android.gms.internal.zzov.zzc
            protected void zza(Context context, zzou zzouVar) throws RemoteException {
                zzouVar.zza(new zzb(this), uri, null, false);
            }
        });
    }

    @Override // com.google.android.gms.panorama.PanoramaApi
    public PendingResult<PanoramaApi.PanoramaResult> loadPanoramaInfoAndGrantAccess(GoogleApiClient client, final Uri uri) {
        return client.zza((GoogleApiClient) new zza(client) { // from class: com.google.android.gms.internal.zzov.2
            @Override // com.google.android.gms.internal.zzov.zzc
            protected void zza(Context context, zzou zzouVar) throws RemoteException {
                zzov.zza(context, zzouVar, new zzb(this), uri, null);
            }
        });
    }
}
