package com.google.android.gms.location.places.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.location.places.AddPlaceRequest;
import com.google.android.gms.location.places.AutocompleteFilter;
import com.google.android.gms.location.places.AutocompletePredictionBuffer;
import com.google.android.gms.location.places.GeoDataApi;
import com.google.android.gms.location.places.PlaceBuffer;
import com.google.android.gms.location.places.Places;
import com.google.android.gms.location.places.zzm;
import com.google.android.gms.maps.model.LatLngBounds;
import java.util.Arrays;
/* loaded from: classes.dex */
public class zzc implements GeoDataApi {
    @Override // com.google.android.gms.location.places.GeoDataApi
    public PendingResult<PlaceBuffer> addPlace(GoogleApiClient client, final AddPlaceRequest addPlaceRequest) {
        return client.zzb(new zzm.zzc<zzd>(Places.zzazQ, client) { // from class: com.google.android.gms.location.places.internal.zzc.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzd zzdVar) throws RemoteException {
                zzdVar.zza(new com.google.android.gms.location.places.zzm(this, zzdVar.getContext()), addPlaceRequest);
            }
        });
    }

    @Override // com.google.android.gms.location.places.GeoDataApi
    public PendingResult<AutocompletePredictionBuffer> getAutocompletePredictions(GoogleApiClient client, final String query, final LatLngBounds bounds, final AutocompleteFilter filter) {
        return client.zza((GoogleApiClient) new zzm.zza<zzd>(Places.zzazQ, client) { // from class: com.google.android.gms.location.places.internal.zzc.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzd zzdVar) throws RemoteException {
                zzdVar.zza(new com.google.android.gms.location.places.zzm(this), query, bounds, filter);
            }
        });
    }

    @Override // com.google.android.gms.location.places.GeoDataApi
    public PendingResult<PlaceBuffer> getPlaceById(GoogleApiClient client, final String... placeIds) {
        boolean z = true;
        com.google.android.gms.common.internal.zzu.zzV((placeIds == null || placeIds.length < 1) ? false : false);
        return client.zza((GoogleApiClient) new zzm.zzc<zzd>(Places.zzazQ, client) { // from class: com.google.android.gms.location.places.internal.zzc.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzd zzdVar) throws RemoteException {
                zzdVar.zza(new com.google.android.gms.location.places.zzm(this, zzdVar.getContext()), Arrays.asList(placeIds));
            }
        });
    }
}
