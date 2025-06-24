package com.google.android.gms.location.internal;

import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.location.LocationServices;
import com.google.android.gms.location.LocationSettingsRequest;
import com.google.android.gms.location.LocationSettingsResult;
import com.google.android.gms.location.SettingsApi;
/* loaded from: classes.dex */
public class zzo implements SettingsApi {
    @Override // com.google.android.gms.location.SettingsApi
    public PendingResult<LocationSettingsResult> checkLocationSettings(GoogleApiClient client, LocationSettingsRequest request) {
        return zza(client, request, null);
    }

    public PendingResult<LocationSettingsResult> zza(GoogleApiClient googleApiClient, final LocationSettingsRequest locationSettingsRequest, final String str) {
        return googleApiClient.zza((GoogleApiClient) new LocationServices.zza<LocationSettingsResult>(googleApiClient) { // from class: com.google.android.gms.location.internal.zzo.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzj zzjVar) throws RemoteException {
                zzjVar.zza(locationSettingsRequest, this, str);
            }

            @Override // com.google.android.gms.common.api.AbstractPendingResult
            /* renamed from: zzaE */
            public LocationSettingsResult createFailedResult(Status status) {
                return new LocationSettingsResult(status);
            }
        });
    }
}
