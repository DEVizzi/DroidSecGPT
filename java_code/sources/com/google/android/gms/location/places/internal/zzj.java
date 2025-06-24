package com.google.android.gms.location.places.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.location.places.PlaceFilter;
import com.google.android.gms.location.places.PlaceReport;
import com.google.android.gms.location.places.PlacesOptions;
import com.google.android.gms.location.places.internal.zze;
import java.util.Locale;
/* loaded from: classes.dex */
public class zzj extends com.google.android.gms.common.internal.zzi<zze> {
    private final PlacesParams zzaAl;
    private final Locale zzaAm;

    /* loaded from: classes.dex */
    public static class zza implements Api.zza<zzj, PlacesOptions> {
        private final String zzaAn;
        private final String zzaAo;

        public zza(String str, String str2) {
            this.zzaAn = str;
            this.zzaAo = str2;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzb */
        public zzj zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, PlacesOptions placesOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzj(context, looper, zzeVar, connectionCallbacks, onConnectionFailedListener, this.zzaAn != null ? this.zzaAn : context.getPackageName(), this.zzaAo != null ? this.zzaAo : context.getPackageName(), placesOptions == null ? new PlacesOptions.Builder().build() : placesOptions);
        }
    }

    public zzj(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, String str, String str2, PlacesOptions placesOptions) {
        super(context, looper, 67, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzaAm = Locale.getDefault();
        this.zzaAl = new PlacesParams(str, this.zzaAm, zzeVar.getAccount() != null ? zzeVar.getAccount().name : null, placesOptions.zzazX, str2);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.location.places.internal.IGooglePlaceDetectionService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.location.places.PlaceDetectionApi";
    }

    public void zza(com.google.android.gms.location.places.zzm zzmVar, PlaceFilter placeFilter) throws RemoteException {
        if (placeFilter == null) {
            placeFilter = PlaceFilter.zzuJ();
        }
        zznM().zza(placeFilter, this.zzaAl, zzmVar);
    }

    public void zza(com.google.android.gms.location.places.zzm zzmVar, PlaceReport placeReport) throws RemoteException {
        com.google.android.gms.common.internal.zzu.zzu(placeReport);
        zznM().zza(placeReport, this.zzaAl, zzmVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzcd */
    public zze zzT(IBinder iBinder) {
        return zze.zza.zzbZ(iBinder);
    }
}
