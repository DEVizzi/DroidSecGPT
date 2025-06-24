package com.google.android.gms.location.places.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.location.places.AddPlaceRequest;
import com.google.android.gms.location.places.AutocompleteFilter;
import com.google.android.gms.location.places.PlacesOptions;
import com.google.android.gms.location.places.internal.zzf;
import com.google.android.gms.maps.model.LatLngBounds;
import java.util.List;
import java.util.Locale;
/* loaded from: classes.dex */
public class zzd extends com.google.android.gms.common.internal.zzi<zzf> {
    private final PlacesParams zzaAl;
    private final Locale zzaAm;

    /* loaded from: classes.dex */
    public static class zza implements Api.zza<zzd, PlacesOptions> {
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
        public zzd zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, PlacesOptions placesOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzd(context, looper, zzeVar, connectionCallbacks, onConnectionFailedListener, this.zzaAn != null ? this.zzaAn : context.getPackageName(), this.zzaAo != null ? this.zzaAo : context.getPackageName(), placesOptions == null ? new PlacesOptions.Builder().build() : placesOptions);
        }
    }

    public zzd(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, String str, String str2, PlacesOptions placesOptions) {
        super(context, looper, 65, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzaAm = Locale.getDefault();
        this.zzaAl = new PlacesParams(str, this.zzaAm, zzeVar.getAccount() != null ? zzeVar.getAccount().name : null, placesOptions.zzazX, str2);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.location.places.internal.IGooglePlacesService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.location.places.GeoDataApi";
    }

    public void zza(com.google.android.gms.location.places.zzm zzmVar, AddPlaceRequest addPlaceRequest) throws RemoteException {
        com.google.android.gms.common.internal.zzu.zzb(addPlaceRequest, "userAddedPlace == null");
        zznM().zza(addPlaceRequest, this.zzaAl, zzmVar);
    }

    public void zza(com.google.android.gms.location.places.zzm zzmVar, String str, LatLngBounds latLngBounds, AutocompleteFilter autocompleteFilter) throws RemoteException {
        com.google.android.gms.common.internal.zzu.zzb(str, "query == null");
        com.google.android.gms.common.internal.zzu.zzb(latLngBounds, "bounds == null");
        com.google.android.gms.common.internal.zzu.zzb(zzmVar, "callback == null");
        zznM().zza(str, latLngBounds, autocompleteFilter == null ? AutocompleteFilter.create(null) : autocompleteFilter, this.zzaAl, zzmVar);
    }

    public void zza(com.google.android.gms.location.places.zzm zzmVar, List<String> list) throws RemoteException {
        zznM().zzb(list, this.zzaAl, zzmVar);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzbY */
    public zzf zzT(IBinder iBinder) {
        return zzf.zza.zzca(iBinder);
    }
}
