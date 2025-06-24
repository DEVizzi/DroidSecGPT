package com.google.android.gms.location;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.location.internal.zzj;
import com.google.android.gms.location.internal.zzo;
/* loaded from: classes.dex */
public class LocationServices {
    private static final Api.ClientKey<zzj> zzNX = new Api.ClientKey<>();
    private static final Api.zza<zzj, Api.ApiOptions.NoOptions> zzNY = new Api.zza<zzj, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.location.LocationServices.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzo */
        public zzj zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzj(context, looper, connectionCallbacks, onConnectionFailedListener, "locationServices", zzeVar);
        }
    };
    public static final Api<Api.ApiOptions.NoOptions> API = new Api<>("LocationServices.API", zzNY, zzNX, new Scope[0]);
    public static final FusedLocationProviderApi FusedLocationApi = new com.google.android.gms.location.internal.zzd();
    public static final GeofencingApi GeofencingApi = new com.google.android.gms.location.internal.zze();
    public static final SettingsApi SettingsApi = new zzo();

    /* loaded from: classes.dex */
    public static abstract class zza<R extends Result> extends zza.AbstractC0032zza<R, zzj> {
        public zza(GoogleApiClient googleApiClient) {
            super(LocationServices.zzNX, googleApiClient);
        }
    }

    private LocationServices() {
    }

    public static zzj zze(GoogleApiClient googleApiClient) {
        zzu.zzb(googleApiClient != null, "GoogleApiClient parameter is required.");
        zzj zzjVar = (zzj) googleApiClient.zza(zzNX);
        zzu.zza(zzjVar != null, "GoogleApiClient is not configured to use the LocationServices.API Api. Pass thisinto GoogleApiClient.Builder#addApi() to use this feature.");
        return zzjVar;
    }
}
