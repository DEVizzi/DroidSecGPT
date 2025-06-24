package com.google.android.gms.location.places;

import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.location.places.internal.zzd;
import com.google.android.gms.location.places.internal.zzj;
/* loaded from: classes.dex */
public class Places {
    public static final Api.ClientKey<com.google.android.gms.location.places.internal.zzd> zzazQ = new Api.ClientKey<>();
    public static final Api.ClientKey<com.google.android.gms.location.places.internal.zzj> zzazR = new Api.ClientKey<>();
    public static final Api<PlacesOptions> GEO_DATA_API = new Api<>("Places.GEO_DATA_API", new zzd.zza(null, null), zzazQ, new Scope[0]);
    public static final Api<PlacesOptions> PLACE_DETECTION_API = new Api<>("Places.PLACE_DETECTION_API", new zzj.zza(null, null), zzazR, new Scope[0]);
    public static final GeoDataApi GeoDataApi = new com.google.android.gms.location.places.internal.zzc();
    public static final PlaceDetectionApi PlaceDetectionApi = new com.google.android.gms.location.places.internal.zzi();

    private Places() {
    }
}
