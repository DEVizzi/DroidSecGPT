package com.google.android.gms.location.internal;

import android.app.PendingIntent;
import android.content.Context;
import android.location.Location;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.location.GeofencingRequest;
import com.google.android.gms.location.LocationAvailability;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationListener;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationSettingsRequest;
import com.google.android.gms.location.LocationSettingsResult;
import com.google.android.gms.location.LocationStatusCodes;
import com.google.android.gms.location.copresence.internal.CopresenceApiOptions;
import com.google.android.gms.location.internal.zzf;
import com.google.android.gms.location.internal.zzh;
import com.google.android.gms.location.zze;
import java.util.List;
/* loaded from: classes.dex */
public class zzj extends com.google.android.gms.location.internal.zzb {
    private final zzi zzayR;
    private final com.google.android.gms.location.copresence.internal.zzb zzayS;

    /* loaded from: classes.dex */
    private final class zza extends com.google.android.gms.common.internal.zzi<zzg>.zzc<zze.zza> {
        private final int zzTS;
        private final String[] zzayT;

        public zza(zze.zza zzaVar, int i, String[] strArr) {
            super(zzaVar);
            this.zzTS = LocationStatusCodes.zzgA(i);
            this.zzayT = strArr;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.internal.zzi.zzc
        /* renamed from: zza */
        public void zzr(zze.zza zzaVar) {
            if (zzaVar != null) {
                zzaVar.zza(this.zzTS, this.zzayT);
            }
        }

        @Override // com.google.android.gms.common.internal.zzi.zzc
        protected void zznP() {
        }
    }

    /* loaded from: classes.dex */
    private static final class zzb extends zzf.zza {
        private zze.zza zzayV;
        private zze.zzb zzayW;
        private zzj zzayX;

        public zzb(zze.zza zzaVar, zzj zzjVar) {
            this.zzayV = zzaVar;
            this.zzayW = null;
            this.zzayX = zzjVar;
        }

        public zzb(zze.zzb zzbVar, zzj zzjVar) {
            this.zzayW = zzbVar;
            this.zzayV = null;
            this.zzayX = zzjVar;
        }

        @Override // com.google.android.gms.location.internal.zzf
        public void zza(int i, PendingIntent pendingIntent) {
            if (this.zzayX == null) {
                Log.wtf("LocationClientImpl", "onRemoveGeofencesByPendingIntentResult called multiple times");
                return;
            }
            zzj zzjVar = this.zzayX;
            zzj zzjVar2 = this.zzayX;
            zzjVar2.getClass();
            zzjVar.zza(new zzc(1, this.zzayW, i, pendingIntent));
            this.zzayX = null;
            this.zzayV = null;
            this.zzayW = null;
        }

        @Override // com.google.android.gms.location.internal.zzf
        public void zza(int i, String[] strArr) throws RemoteException {
            if (this.zzayX == null) {
                Log.wtf("LocationClientImpl", "onAddGeofenceResult called multiple times");
                return;
            }
            zzj zzjVar = this.zzayX;
            zzj zzjVar2 = this.zzayX;
            zzjVar2.getClass();
            zzjVar.zza(new zza(this.zzayV, i, strArr));
            this.zzayX = null;
            this.zzayV = null;
            this.zzayW = null;
        }

        @Override // com.google.android.gms.location.internal.zzf
        public void zzb(int i, String[] strArr) {
            if (this.zzayX == null) {
                Log.wtf("LocationClientImpl", "onRemoveGeofencesByRequestIdsResult called multiple times");
                return;
            }
            zzj zzjVar = this.zzayX;
            zzj zzjVar2 = this.zzayX;
            zzjVar2.getClass();
            zzjVar.zza(new zzc(2, this.zzayW, i, strArr));
            this.zzayX = null;
            this.zzayV = null;
            this.zzayW = null;
        }
    }

    /* loaded from: classes.dex */
    private final class zzc extends com.google.android.gms.common.internal.zzi<zzg>.zzc<zze.zzb> {
        private final PendingIntent mPendingIntent;
        private final int zzTS;
        private final String[] zzayT;
        private final int zzayY;

        public zzc(int i, zze.zzb zzbVar, int i2, PendingIntent pendingIntent) {
            super(zzbVar);
            com.google.android.gms.common.internal.zzb.zzU(i == 1);
            this.zzayY = i;
            this.zzTS = LocationStatusCodes.zzgA(i2);
            this.mPendingIntent = pendingIntent;
            this.zzayT = null;
        }

        public zzc(int i, zze.zzb zzbVar, int i2, String[] strArr) {
            super(zzbVar);
            com.google.android.gms.common.internal.zzb.zzU(i == 2);
            this.zzayY = i;
            this.zzTS = LocationStatusCodes.zzgA(i2);
            this.zzayT = strArr;
            this.mPendingIntent = null;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.internal.zzi.zzc
        /* renamed from: zza */
        public void zzr(zze.zzb zzbVar) {
            if (zzbVar != null) {
                switch (this.zzayY) {
                    case 1:
                        zzbVar.zza(this.zzTS, this.mPendingIntent);
                        return;
                    case 2:
                        zzbVar.zzb(this.zzTS, this.zzayT);
                        return;
                    default:
                        Log.wtf("LocationClientImpl", "Unsupported action: " + this.zzayY);
                        return;
                }
            }
        }

        @Override // com.google.android.gms.common.internal.zzi.zzc
        protected void zznP() {
        }
    }

    /* loaded from: classes.dex */
    private static final class zzd extends zzh.zza {
        private zza.zzb<LocationSettingsResult> zzayZ;

        public zzd(zza.zzb<LocationSettingsResult> zzbVar) {
            zzu.zzb(zzbVar != null, "listener can't be null.");
            this.zzayZ = zzbVar;
        }

        @Override // com.google.android.gms.location.internal.zzh
        public void zza(LocationSettingsResult locationSettingsResult) throws RemoteException {
            this.zzayZ.zzm(locationSettingsResult);
            this.zzayZ = null;
        }
    }

    public zzj(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, String str) {
        this(context, looper, connectionCallbacks, onConnectionFailedListener, str, new GoogleApiClient.Builder(context).zzmx());
    }

    public zzj(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, String str, com.google.android.gms.common.internal.zze zzeVar) {
        this(context, looper, connectionCallbacks, onConnectionFailedListener, str, zzeVar, CopresenceApiOptions.zzayn);
    }

    public zzj(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, String str, com.google.android.gms.common.internal.zze zzeVar, CopresenceApiOptions copresenceApiOptions) {
        super(context, looper, connectionCallbacks, onConnectionFailedListener, str, zzeVar);
        this.zzayR = new zzi(context, this.zzayq);
        this.zzayS = com.google.android.gms.location.copresence.internal.zzb.zza(context, zzeVar.getAccountName(), zzeVar.zzny(), this.zzayq, copresenceApiOptions);
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        synchronized (this.zzayR) {
            if (isConnected()) {
                try {
                    this.zzayR.removeAllListeners();
                    this.zzayR.zzux();
                } catch (Exception e) {
                    Log.e("LocationClientImpl", "Client disconnected before listeners could be cleaned up", e);
                }
            }
            super.disconnect();
        }
    }

    public Location getLastLocation() {
        return this.zzayR.getLastLocation();
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresAccount() {
        return true;
    }

    public void zza(long j, PendingIntent pendingIntent) throws RemoteException {
        zznL();
        zzu.zzu(pendingIntent);
        zzu.zzb(j >= 0, "detectionIntervalMillis must be >= 0");
        zznM().zza(j, true, pendingIntent);
    }

    public void zza(PendingIntent pendingIntent) throws RemoteException {
        zznL();
        zzu.zzu(pendingIntent);
        zznM().zza(pendingIntent);
    }

    public void zza(PendingIntent pendingIntent, zze.zzb zzbVar) throws RemoteException {
        zznL();
        zzu.zzb(pendingIntent, "PendingIntent must be specified.");
        zzu.zzb(zzbVar, "OnRemoveGeofencesResultListener not provided.");
        zznM().zza(pendingIntent, zzbVar == null ? null : new zzb(zzbVar, this), getContext().getPackageName());
    }

    public void zza(GeofencingRequest geofencingRequest, PendingIntent pendingIntent, zze.zza zzaVar) throws RemoteException {
        zznL();
        zzu.zzb(geofencingRequest, "geofencingRequest can't be null.");
        zzu.zzb(pendingIntent, "PendingIntent must be specified.");
        zzu.zzb(zzaVar, "OnAddGeofencesResultListener not provided.");
        zznM().zza(geofencingRequest, pendingIntent, zzaVar == null ? null : new zzb(zzaVar, this));
    }

    public void zza(LocationCallback locationCallback) throws RemoteException {
        this.zzayR.zza(locationCallback);
    }

    public void zza(LocationListener locationListener) throws RemoteException {
        this.zzayR.zza(locationListener);
    }

    public void zza(LocationRequest locationRequest, LocationListener locationListener, Looper looper) throws RemoteException {
        synchronized (this.zzayR) {
            this.zzayR.zza(locationRequest, locationListener, looper);
        }
    }

    public void zza(LocationSettingsRequest locationSettingsRequest, zza.zzb<LocationSettingsResult> zzbVar, String str) throws RemoteException {
        zznL();
        zzu.zzb(locationSettingsRequest != null, "locationSettingsRequest can't be null nor empty.");
        zzu.zzb(zzbVar != null, "listener can't be null.");
        zznM().zza(locationSettingsRequest, new zzd(zzbVar), str);
    }

    public void zza(LocationRequestInternal locationRequestInternal, LocationCallback locationCallback, Looper looper) throws RemoteException {
        synchronized (this.zzayR) {
            this.zzayR.zza(locationRequestInternal, locationCallback, looper);
        }
    }

    public void zza(List<String> list, zze.zzb zzbVar) throws RemoteException {
        zznL();
        zzu.zzb(list != null && list.size() > 0, "geofenceRequestIds can't be null nor empty.");
        zzu.zzb(zzbVar, "OnRemoveGeofencesResultListener not provided.");
        zznM().zza((String[]) list.toArray(new String[0]), zzbVar == null ? null : new zzb(zzbVar, this), getContext().getPackageName());
    }

    public void zzac(boolean z) throws RemoteException {
        this.zzayR.zzac(z);
    }

    public void zzb(Location location) throws RemoteException {
        this.zzayR.zzb(location);
    }

    public void zzb(LocationRequest locationRequest, PendingIntent pendingIntent) throws RemoteException {
        this.zzayR.zzb(locationRequest, pendingIntent);
    }

    public void zzd(PendingIntent pendingIntent) throws RemoteException {
        this.zzayR.zzd(pendingIntent);
    }

    public LocationAvailability zzuw() {
        return this.zzayR.zzuw();
    }
}
