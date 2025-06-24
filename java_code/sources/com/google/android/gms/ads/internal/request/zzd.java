package com.google.android.gms.ads.internal.request;

import android.content.Context;
import android.os.Binder;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.request.zzc;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zzbr;
import com.google.android.gms.internal.zzbz;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzge;
import com.google.android.gms.internal.zzgf;
import com.google.android.gms.internal.zzhh;
@zzgd
/* loaded from: classes.dex */
public abstract class zzd extends zzhh implements zzc.zza {
    private AdResponseParcel zzBt;
    private final zzc.zza zzCi;
    private final Object zzqt = new Object();
    private final AdRequestInfoParcel zzxm;

    @zzgd
    /* loaded from: classes.dex */
    public static final class zza extends zzd {
        private final Context mContext;

        public zza(Context context, AdRequestInfoParcel adRequestInfoParcel, zzc.zza zzaVar) {
            super(adRequestInfoParcel, zzaVar);
            this.mContext = context;
        }

        @Override // com.google.android.gms.ads.internal.request.zzd
        public void zzfv() {
        }

        @Override // com.google.android.gms.ads.internal.request.zzd
        public zzi zzfw() {
            return zzgf.zza(this.mContext, new zzbr(zzbz.zztD.get()), zzge.zzfC());
        }
    }

    @zzgd
    /* loaded from: classes.dex */
    public static class zzb extends zzd implements GoogleApiClient.ConnectionCallbacks, GoogleApiClient.OnConnectionFailedListener {
        private Context mContext;
        private final zzc.zza zzCi;
        protected zze zzCj;
        private final Object zzqt;
        private AdRequestInfoParcel zzxm;

        public zzb(Context context, AdRequestInfoParcel adRequestInfoParcel, zzc.zza zzaVar) {
            super(adRequestInfoParcel, zzaVar);
            this.zzqt = new Object();
            this.mContext = context;
            this.zzxm = adRequestInfoParcel;
            this.zzCi = zzaVar;
            this.zzCj = new zze(context, this, this, adRequestInfoParcel.zzpJ.zzGI);
            connect();
        }

        protected void connect() {
            this.zzCj.zznJ();
        }

        @Override // com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks
        public void onConnected(Bundle connectionHint) {
            zzgi();
        }

        @Override // com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener
        public void onConnectionFailed(ConnectionResult result) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Cannot connect to remote service, fallback to local instance.");
            zzfx().zzgi();
            Bundle bundle = new Bundle();
            bundle.putString("action", "gms_connection_failed_fallback_to_local");
            zzo.zzbv().zza(this.mContext, this.zzxm.zzpJ.zzGG, "gmob-apps", bundle, true);
        }

        @Override // com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks
        public void onConnectionSuspended(int cause) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("Disconnected from remote ad request service.");
        }

        @Override // com.google.android.gms.ads.internal.request.zzd
        public void zzfv() {
            synchronized (this.zzqt) {
                if (this.zzCj.isConnected() || this.zzCj.isConnecting()) {
                    this.zzCj.disconnect();
                }
                Binder.flushPendingCommands();
            }
        }

        @Override // com.google.android.gms.ads.internal.request.zzd
        public zzi zzfw() {
            zzi zziVar;
            synchronized (this.zzqt) {
                try {
                    zziVar = this.zzCj.zzfy();
                } catch (DeadObjectException | IllegalStateException e) {
                    zziVar = null;
                }
            }
            return zziVar;
        }

        zzhh zzfx() {
            return new zza(this.mContext, this.zzxm, this.zzCi);
        }
    }

    public zzd(AdRequestInfoParcel adRequestInfoParcel, zzc.zza zzaVar) {
        this.zzxm = adRequestInfoParcel;
        this.zzCi = zzaVar;
    }

    @Override // com.google.android.gms.internal.zzhh
    public final void onStop() {
        zzfv();
    }

    boolean zza(zzi zziVar, AdRequestInfoParcel adRequestInfoParcel) {
        try {
            zziVar.zza(adRequestInfoParcel, new zzg(this));
            return true;
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not fetch ad response from ad request service.", e);
            zzo.zzby().zzc((Throwable) e, true);
            this.zzCi.zzb(new AdResponseParcel(0));
            return false;
        } catch (NullPointerException e2) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not fetch ad response from ad request service due to an Exception.", e2);
            zzo.zzby().zzc((Throwable) e2, true);
            this.zzCi.zzb(new AdResponseParcel(0));
            return false;
        } catch (SecurityException e3) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not fetch ad response from ad request service due to an Exception.", e3);
            zzo.zzby().zzc((Throwable) e3, true);
            this.zzCi.zzb(new AdResponseParcel(0));
            return false;
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Could not fetch ad response from ad request service due to an Exception.", th);
            zzo.zzby().zzc(th, true);
            this.zzCi.zzb(new AdResponseParcel(0));
            return false;
        }
    }

    @Override // com.google.android.gms.ads.internal.request.zzc.zza
    public void zzb(AdResponseParcel adResponseParcel) {
        synchronized (this.zzqt) {
            this.zzBt = adResponseParcel;
            this.zzqt.notify();
        }
    }

    @Override // com.google.android.gms.internal.zzhh
    public void zzdP() {
        try {
            zzi zzfw = zzfw();
            if (zzfw == null) {
                this.zzCi.zzb(new AdResponseParcel(0));
            } else if (zza(zzfw, this.zzxm)) {
                zzi(zzo.zzbz().elapsedRealtime());
            }
        } finally {
            zzfv();
        }
    }

    protected boolean zze(long j) {
        long elapsedRealtime = 60000 - (zzo.zzbz().elapsedRealtime() - j);
        if (elapsedRealtime <= 0) {
            return false;
        }
        try {
            this.zzqt.wait(elapsedRealtime);
            return true;
        } catch (InterruptedException e) {
            return false;
        }
    }

    public abstract void zzfv();

    public abstract zzi zzfw();

    protected void zzi(long j) {
        synchronized (this.zzqt) {
            do {
                if (this.zzBt != null) {
                    this.zzCi.zzb(this.zzBt);
                    return;
                }
            } while (zze(j));
            if (this.zzBt != null) {
                this.zzCi.zzb(this.zzBt);
            } else {
                this.zzCi.zzb(new AdResponseParcel(0));
            }
        }
    }
}
