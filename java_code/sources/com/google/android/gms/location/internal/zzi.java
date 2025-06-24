package com.google.android.gms.location.internal;

import android.app.PendingIntent;
import android.content.ContentProviderClient;
import android.content.Context;
import android.location.Location;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.location.LocationAvailability;
import com.google.android.gms.location.LocationCallback;
import com.google.android.gms.location.LocationListener;
import com.google.android.gms.location.LocationRequest;
import com.google.android.gms.location.LocationResult;
import com.google.android.gms.location.zzc;
import com.google.android.gms.location.zzd;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public class zzi {
    private final Context mContext;
    private final zzn<zzg> zzayq;
    private ContentProviderClient zzayL = null;
    private boolean zzayM = false;
    private Map<LocationListener, zzc> zzakE = new HashMap();
    private Map<LocationCallback, zza> zzayN = new HashMap();

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zza extends zzc.zza {
        private Handler zzayO;

        zza(final LocationCallback locationCallback, Looper looper) {
            if (looper == null) {
                looper = Looper.myLooper();
                zzu.zza(looper != null, "Can't create handler inside thread that has not called Looper.prepare()");
            }
            this.zzayO = new Handler(looper) { // from class: com.google.android.gms.location.internal.zzi.zza.1
                @Override // android.os.Handler
                public void handleMessage(Message msg) {
                    switch (msg.what) {
                        case 0:
                            locationCallback.onLocationResult((LocationResult) msg.obj);
                            return;
                        case 1:
                            locationCallback.onLocationAvailability((LocationAvailability) msg.obj);
                            return;
                        default:
                            return;
                    }
                }
            };
        }

        private void zzb(int i, Object obj) {
            if (this.zzayO == null) {
                Log.e("LocationClientHelper", "Received a data in client after calling removeLocationUpdates.");
                return;
            }
            Message obtain = Message.obtain();
            obtain.what = i;
            obtain.obj = obj;
            this.zzayO.sendMessage(obtain);
        }

        @Override // com.google.android.gms.location.zzc
        public void onLocationAvailability(LocationAvailability state) {
            zzb(1, state);
        }

        @Override // com.google.android.gms.location.zzc
        public void onLocationResult(LocationResult locationResult) {
            zzb(0, locationResult);
        }

        public void release() {
            this.zzayO = null;
        }
    }

    /* loaded from: classes.dex */
    private static class zzb extends Handler {
        private final LocationListener zzayQ;

        public zzb(LocationListener locationListener) {
            this.zzayQ = locationListener;
        }

        public zzb(LocationListener locationListener, Looper looper) {
            super(looper);
            this.zzayQ = locationListener;
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case 1:
                    this.zzayQ.onLocationChanged(new Location((Location) msg.obj));
                    return;
                default:
                    Log.e("LocationClientHelper", "unknown message in LocationHandler.handleMessage");
                    return;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzc extends zzd.zza {
        private Handler zzayO;

        zzc(LocationListener locationListener, Looper looper) {
            if (looper == null) {
                zzu.zza(Looper.myLooper() != null, "Can't create handler inside thread that has not called Looper.prepare()");
            }
            this.zzayO = looper == null ? new zzb(locationListener) : new zzb(locationListener, looper);
        }

        @Override // com.google.android.gms.location.zzd
        public void onLocationChanged(Location location) {
            if (this.zzayO == null) {
                Log.e("LocationClientHelper", "Received a location in client after calling removeLocationUpdates.");
                return;
            }
            Message obtain = Message.obtain();
            obtain.what = 1;
            obtain.obj = location;
            this.zzayO.sendMessage(obtain);
        }

        public void release() {
            this.zzayO = null;
        }
    }

    public zzi(Context context, zzn<zzg> zznVar) {
        this.mContext = context;
        this.zzayq = zznVar;
    }

    private zza zza(LocationCallback locationCallback, Looper looper) {
        zza zzaVar;
        synchronized (this.zzakE) {
            zzaVar = this.zzayN.get(locationCallback);
            if (zzaVar == null) {
                zzaVar = new zza(locationCallback, looper);
            }
            this.zzayN.put(locationCallback, zzaVar);
        }
        return zzaVar;
    }

    private zzc zza(LocationListener locationListener, Looper looper) {
        zzc zzcVar;
        synchronized (this.zzakE) {
            zzcVar = this.zzakE.get(locationListener);
            if (zzcVar == null) {
                zzcVar = new zzc(locationListener, looper);
            }
            this.zzakE.put(locationListener, zzcVar);
        }
        return zzcVar;
    }

    public Location getLastLocation() {
        this.zzayq.zznL();
        try {
            return this.zzayq.zznM().zzdl(this.mContext.getPackageName());
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }

    public void removeAllListeners() {
        try {
            synchronized (this.zzakE) {
                for (zzc zzcVar : this.zzakE.values()) {
                    if (zzcVar != null) {
                        this.zzayq.zznM().zza(LocationRequestUpdateData.zzb(zzcVar));
                    }
                }
                this.zzakE.clear();
                for (zza zzaVar : this.zzayN.values()) {
                    if (zzaVar != null) {
                        this.zzayq.zznM().zza(LocationRequestUpdateData.zza(zzaVar));
                    }
                }
                this.zzayN.clear();
            }
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }

    public void zza(LocationCallback locationCallback) throws RemoteException {
        this.zzayq.zznL();
        zzu.zzb(locationCallback, "Invalid null callback");
        synchronized (this.zzayN) {
            zza remove = this.zzayN.remove(locationCallback);
            if (remove != null) {
                remove.release();
                this.zzayq.zznM().zza(LocationRequestUpdateData.zza(remove));
            }
        }
    }

    public void zza(LocationListener locationListener) throws RemoteException {
        this.zzayq.zznL();
        zzu.zzb(locationListener, "Invalid null listener");
        synchronized (this.zzakE) {
            zzc remove = this.zzakE.remove(locationListener);
            if (this.zzayL != null && this.zzakE.isEmpty()) {
                this.zzayL.release();
                this.zzayL = null;
            }
            if (remove != null) {
                remove.release();
                this.zzayq.zznM().zza(LocationRequestUpdateData.zzb(remove));
            }
        }
    }

    public void zza(LocationRequest locationRequest, LocationListener locationListener, Looper looper) throws RemoteException {
        this.zzayq.zznL();
        this.zzayq.zznM().zza(LocationRequestUpdateData.zzb(LocationRequestInternal.zzb(locationRequest), zza(locationListener, looper)));
    }

    public void zza(LocationRequestInternal locationRequestInternal, LocationCallback locationCallback, Looper looper) throws RemoteException {
        this.zzayq.zznL();
        this.zzayq.zznM().zza(LocationRequestUpdateData.zza(locationRequestInternal, zza(locationCallback, looper)));
    }

    public void zzac(boolean z) throws RemoteException {
        this.zzayq.zznL();
        this.zzayq.zznM().zzac(z);
        this.zzayM = z;
    }

    public void zzb(Location location) throws RemoteException {
        this.zzayq.zznL();
        this.zzayq.zznM().zzb(location);
    }

    public void zzb(LocationRequest locationRequest, PendingIntent pendingIntent) throws RemoteException {
        this.zzayq.zznL();
        this.zzayq.zznM().zza(LocationRequestUpdateData.zzb(LocationRequestInternal.zzb(locationRequest), pendingIntent));
    }

    public void zzd(PendingIntent pendingIntent) throws RemoteException {
        this.zzayq.zznL();
        this.zzayq.zznM().zza(LocationRequestUpdateData.zze(pendingIntent));
    }

    public LocationAvailability zzuw() {
        this.zzayq.zznL();
        try {
            return this.zzayq.zznM().zzdm(this.mContext.getPackageName());
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }

    public void zzux() {
        if (this.zzayM) {
            try {
                zzac(false);
            } catch (RemoteException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
