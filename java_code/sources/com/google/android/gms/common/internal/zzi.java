package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.Handler;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import android.os.Message;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.zzj;
import com.google.android.gms.common.internal.zzo;
import com.google.android.gms.common.internal.zzp;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
/* loaded from: classes.dex */
public abstract class zzi<T extends IInterface> implements Api.Client, zzj.zza {
    public static final String[] zzaav = {"service_esmobile", "service_googleme"};
    private final Context mContext;
    final Handler mHandler;
    private final Account zzMY;
    private final Set<Scope> zzWJ;
    private final Looper zzWt;
    private final com.google.android.gms.common.internal.zze zzXa;
    private final zzk zzaak;
    private zzp zzaal;
    private GoogleApiClient.ConnectionProgressReportCallbacks zzaam;
    private T zzaan;
    private final ArrayList<zzi<T>.zzc<?>> zzaao;
    private zzi<T>.zze zzaap;
    private int zzaaq;
    private GoogleApiClient.ConnectionCallbacks zzaar;
    private GoogleApiClient.OnConnectionFailedListener zzaas;
    private final int zzaat;
    protected AtomicInteger zzaau;
    private final Object zzqt;

    /* loaded from: classes.dex */
    private abstract class zza extends zzi<T>.zzc<Boolean> {
        public final int statusCode;
        public final Bundle zzaaw;

        protected zza(int i, Bundle bundle) {
            super(true);
            this.statusCode = i;
            this.zzaaw = bundle;
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.internal.zzi.zzc
        /* renamed from: zzc */
        public void zzr(Boolean bool) {
            if (bool == null) {
                zzi.this.zza(1, (int) null);
                return;
            }
            switch (this.statusCode) {
                case 0:
                    if (zznO()) {
                        return;
                    }
                    zzi.this.zza(1, (int) null);
                    zzg(new ConnectionResult(8, null));
                    return;
                case 10:
                    zzi.this.zza(1, (int) null);
                    throw new IllegalStateException("A fatal developer error has occurred. Check the logs for further information.");
                default:
                    zzi.this.zza(1, (int) null);
                    zzg(new ConnectionResult(this.statusCode, this.zzaaw != null ? (PendingIntent) this.zzaaw.getParcelable("pendingIntent") : null));
                    return;
            }
        }

        protected abstract void zzg(ConnectionResult connectionResult);

        protected abstract boolean zznO();

        @Override // com.google.android.gms.common.internal.zzi.zzc
        protected void zznP() {
        }
    }

    /* loaded from: classes.dex */
    final class zzb extends Handler {
        public zzb(Looper looper) {
            super(looper);
        }

        private void zza(Message message) {
            zzc zzcVar = (zzc) message.obj;
            zzcVar.zznP();
            zzcVar.unregister();
        }

        private boolean zzb(Message message) {
            return message.what == 2 || message.what == 1 || message.what == 5 || message.what == 6;
        }

        @Override // android.os.Handler
        public void handleMessage(Message msg) {
            if (zzi.this.zzaau.get() != msg.arg1) {
                if (zzb(msg)) {
                    zza(msg);
                }
            } else if ((msg.what == 1 || msg.what == 5 || msg.what == 6) && !zzi.this.isConnecting()) {
                zza(msg);
            } else if (msg.what == 3) {
                ConnectionResult connectionResult = new ConnectionResult(msg.arg2, null);
                zzi.this.zzaam.onReportServiceBinding(connectionResult);
                zzi.this.onConnectionFailed(connectionResult);
            } else if (msg.what == 4) {
                zzi.this.zza(4, (int) null);
                if (zzi.this.zzaar != null) {
                    zzi.this.zzaar.onConnectionSuspended(msg.arg2);
                }
                zzi.this.onConnectionSuspended(msg.arg2);
                zzi.this.zza(4, 1, (int) null);
            } else if (msg.what == 2 && !zzi.this.isConnected()) {
                zza(msg);
            } else if (zzb(msg)) {
                ((zzc) msg.obj).zznQ();
            } else {
                Log.wtf("GmsClient", "Don't know how to handle this message.");
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public abstract class zzc<TListener> {
        private TListener mListener;
        private boolean zzaay = false;

        public zzc(TListener tlistener) {
            this.mListener = tlistener;
        }

        public void unregister() {
            zznR();
            synchronized (zzi.this.zzaao) {
                zzi.this.zzaao.remove(this);
            }
        }

        protected abstract void zznP();

        public void zznQ() {
            TListener tlistener;
            synchronized (this) {
                tlistener = this.mListener;
                if (this.zzaay) {
                    Log.w("GmsClient", "Callback proxy " + this + " being reused. This is not safe.");
                }
            }
            if (tlistener != null) {
                try {
                    zzr(tlistener);
                } catch (RuntimeException e) {
                    zznP();
                    throw e;
                }
            } else {
                zznP();
            }
            synchronized (this) {
                this.zzaay = true;
            }
            unregister();
        }

        public void zznR() {
            synchronized (this) {
                this.mListener = null;
            }
        }

        protected abstract void zzr(TListener tlistener);
    }

    /* loaded from: classes.dex */
    public static final class zzd extends zzo.zza {
        private final int zzaaA;
        private zzi zzaaz;

        public zzd(zzi zziVar, int i) {
            this.zzaaz = zziVar;
            this.zzaaA = i;
        }

        private void zznS() {
            this.zzaaz = null;
        }

        @Override // com.google.android.gms.common.internal.zzo
        public void zza(int i, IBinder iBinder, Bundle bundle) {
            zzu.zzb(this.zzaaz, "onPostInitComplete can be called only once per call to getRemoteService");
            this.zzaaz.zza(i, iBinder, bundle, this.zzaaA);
            zznS();
        }

        @Override // com.google.android.gms.common.internal.zzo
        public void zzb(int i, Bundle bundle) {
            zzu.zzb(this.zzaaz, "onAccountValidationComplete can be called only once per call to validateAccount");
            this.zzaaz.zza(i, bundle, this.zzaaA);
            zznS();
        }
    }

    /* loaded from: classes.dex */
    public final class zze implements ServiceConnection {
        private final int zzaaA;

        public zze(int i) {
            this.zzaaA = i;
        }

        @Override // android.content.ServiceConnection
        public void onServiceConnected(ComponentName component, IBinder binder) {
            zzu.zzb(binder, "Expecting a valid IBinder");
            zzi.this.zzaal = zzp.zza.zzaG(binder);
            zzi.this.zzbt(this.zzaaA);
        }

        @Override // android.content.ServiceConnection
        public void onServiceDisconnected(ComponentName component) {
            zzi.this.mHandler.sendMessage(zzi.this.mHandler.obtainMessage(4, this.zzaaA, 1));
        }
    }

    /* loaded from: classes.dex */
    protected class zzf implements GoogleApiClient.ConnectionProgressReportCallbacks {
        public zzf() {
        }

        @Override // com.google.android.gms.common.api.GoogleApiClient.ConnectionProgressReportCallbacks
        public void onReportAccountValidation(ConnectionResult result) {
            throw new IllegalStateException("Legacy GmsClient received onReportAccountValidation callback.");
        }

        @Override // com.google.android.gms.common.api.GoogleApiClient.ConnectionProgressReportCallbacks
        public void onReportServiceBinding(ConnectionResult result) {
            if (result.isSuccess()) {
                zzi.this.getRemoteService(null, zzi.this.zzWJ);
            } else if (zzi.this.zzaas != null) {
                zzi.this.zzaas.onConnectionFailed(result);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public final class zzg extends zzi<T>.zza {
        public final IBinder zzaaB;

        public zzg(int i, IBinder iBinder, Bundle bundle) {
            super(i, bundle);
            this.zzaaB = iBinder;
        }

        @Override // com.google.android.gms.common.internal.zzi.zza
        protected void zzg(ConnectionResult connectionResult) {
            if (zzi.this.zzaas != null) {
                zzi.this.zzaas.onConnectionFailed(connectionResult);
            }
            zzi.this.onConnectionFailed(connectionResult);
        }

        @Override // com.google.android.gms.common.internal.zzi.zza
        protected boolean zznO() {
            try {
                String interfaceDescriptor = this.zzaaB.getInterfaceDescriptor();
                if (!zzi.this.getServiceDescriptor().equals(interfaceDescriptor)) {
                    Log.e("GmsClient", "service descriptor mismatch: " + zzi.this.getServiceDescriptor() + " vs. " + interfaceDescriptor);
                    return false;
                }
                IInterface zzT = zzi.this.zzT(this.zzaaB);
                if (zzT == null || !zzi.this.zza(2, 3, (int) zzT)) {
                    return false;
                }
                Bundle zzlM = zzi.this.zzlM();
                if (zzi.this.zzaar != null) {
                    zzi.this.zzaar.onConnected(zzlM);
                }
                GooglePlayServicesUtil.zzac(zzi.this.mContext);
                return true;
            } catch (RemoteException e) {
                Log.w("GmsClient", "service probably died");
                return false;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* loaded from: classes.dex */
    public final class zzh extends zzi<T>.zza {
        public zzh() {
            super(0, null);
        }

        @Override // com.google.android.gms.common.internal.zzi.zza
        protected void zzg(ConnectionResult connectionResult) {
            zzi.this.zzaam.onReportServiceBinding(connectionResult);
            zzi.this.onConnectionFailed(connectionResult);
        }

        @Override // com.google.android.gms.common.internal.zzi.zza
        protected boolean zznO() {
            zzi.this.zzaam.onReportServiceBinding(ConnectionResult.zzVG);
            return true;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    /* renamed from: com.google.android.gms.common.internal.zzi$zzi  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public final class C0037zzi extends zzi<T>.zza {
        public C0037zzi(int i, Bundle bundle) {
            super(i, bundle);
        }

        @Override // com.google.android.gms.common.internal.zzi.zza
        protected void zzg(ConnectionResult connectionResult) {
            zzi.this.zzaam.onReportAccountValidation(connectionResult);
            zzi.this.onConnectionFailed(connectionResult);
        }

        @Override // com.google.android.gms.common.internal.zzi.zza
        protected boolean zznO() {
            zzi.this.zzaam.onReportAccountValidation(ConnectionResult.zzVG);
            return true;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Deprecated
    public zzi(Context context, Looper looper, int i, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        this.zzqt = new Object();
        this.zzaao = new ArrayList<>();
        this.zzaaq = 1;
        this.zzaau = new AtomicInteger(0);
        this.mContext = (Context) zzu.zzu(context);
        this.zzWt = (Looper) zzu.zzb(looper, "Looper must not be null");
        this.zzaak = zzk.zzah(context);
        this.mHandler = new zzb(looper);
        this.zzaat = i;
        this.zzMY = null;
        this.zzWJ = Collections.emptySet();
        this.zzXa = new GoogleApiClient.Builder(context).zzmx();
        this.zzaar = (GoogleApiClient.ConnectionCallbacks) zzu.zzu(connectionCallbacks);
        this.zzaas = (GoogleApiClient.OnConnectionFailedListener) zzu.zzu(onConnectionFailedListener);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzi(Context context, Looper looper, int i, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, com.google.android.gms.common.internal.zze zzeVar) {
        this(context, looper, zzk.zzah(context), i, zzeVar, connectionCallbacks, onConnectionFailedListener);
    }

    protected zzi(Context context, Looper looper, zzk zzkVar, int i, com.google.android.gms.common.internal.zze zzeVar) {
        this.zzqt = new Object();
        this.zzaao = new ArrayList<>();
        this.zzaaq = 1;
        this.zzaau = new AtomicInteger(0);
        this.mContext = (Context) zzu.zzb(context, "Context must not be null");
        this.zzWt = (Looper) zzu.zzb(looper, "Looper must not be null");
        this.zzaak = (zzk) zzu.zzb(zzkVar, "Supervisor must not be null");
        this.mHandler = new zzb(looper);
        this.zzaat = i;
        this.zzXa = (com.google.android.gms.common.internal.zze) zzu.zzu(zzeVar);
        this.zzMY = zzeVar.getAccount();
        this.zzWJ = zzb(zzeVar.zznw());
    }

    protected zzi(Context context, Looper looper, zzk zzkVar, int i, com.google.android.gms.common.internal.zze zzeVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        this(context, looper, zzkVar, i, zzeVar);
        this.zzaar = (GoogleApiClient.ConnectionCallbacks) zzu.zzu(connectionCallbacks);
        this.zzaas = (GoogleApiClient.OnConnectionFailedListener) zzu.zzu(onConnectionFailedListener);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zza(int i, T t) {
        zzu.zzV((i == 3) == (t != null));
        synchronized (this.zzqt) {
            this.zzaaq = i;
            this.zzaan = t;
            switch (i) {
                case 1:
                    zznI();
                    break;
                case 2:
                    zznH();
                    break;
                case 3:
                    zznG();
                    break;
            }
        }
    }

    private void zza(GoogleApiClient.ConnectionProgressReportCallbacks connectionProgressReportCallbacks) {
        this.zzaam = (GoogleApiClient.ConnectionProgressReportCallbacks) zzu.zzb(connectionProgressReportCallbacks, "Connection progress callbacks cannot be null.");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean zza(int i, int i2, T t) {
        boolean z;
        synchronized (this.zzqt) {
            if (this.zzaaq != i) {
                z = false;
            } else {
                zza(i2, (int) t);
                z = true;
            }
        }
        return z;
    }

    private Set<Scope> zzb(Set<Scope> set) {
        Set<Scope> zza2 = zza(set);
        if (zza2 == null) {
            return zza2;
        }
        for (Scope scope : zza2) {
            if (!set.contains(scope)) {
                throw new IllegalStateException("Expanding scopes is not permitted, use implied scopes instead");
            }
        }
        return zza2;
    }

    private void zznH() {
        if (this.zzaap != null) {
            Log.e("GmsClient", "Calling connect() while still connected, missing disconnect() for " + getStartServiceAction());
            this.zzaak.zzb(getStartServiceAction(), this.zzaap, zzkQ());
            this.zzaau.incrementAndGet();
        }
        this.zzaap = new zze(this.zzaau.get());
        if (this.zzaak.zza(getStartServiceAction(), this.zzaap, zzkQ())) {
            return;
        }
        Log.e("GmsClient", "unable to connect to service: " + getStartServiceAction());
        this.mHandler.sendMessage(this.mHandler.obtainMessage(3, this.zzaau.get(), 9));
    }

    private void zznI() {
        if (this.zzaap != null) {
            this.zzaak.zzb(getStartServiceAction(), this.zzaap, zzkQ());
            this.zzaap = null;
        }
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public void connect(GoogleApiClient.ConnectionProgressReportCallbacks callbacks) {
        zza(callbacks);
        zza(2, (int) null);
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        this.zzaau.incrementAndGet();
        synchronized (this.zzaao) {
            int size = this.zzaao.size();
            for (int i = 0; i < size; i++) {
                this.zzaao.get(i).zznR();
            }
            this.zzaao.clear();
        }
        zza(1, (int) null);
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public void dump(String prefix, FileDescriptor fd, PrintWriter writer, String[] args) {
        int i;
        T t;
        synchronized (this.zzqt) {
            i = this.zzaaq;
            t = this.zzaan;
        }
        writer.append((CharSequence) prefix).append("mConnectState=");
        switch (i) {
            case 1:
                writer.print("DISCONNECTED");
                break;
            case 2:
                writer.print("CONNECTING");
                break;
            case 3:
                writer.print("CONNECTED");
                break;
            case 4:
                writer.print("DISCONNECTING");
                break;
            default:
                writer.print("UNKNOWN");
                break;
        }
        writer.append(" mService=");
        if (t == null) {
            writer.println("null");
        } else {
            writer.append((CharSequence) getServiceDescriptor()).append("@").println(Integer.toHexString(System.identityHashCode(t.asBinder())));
        }
    }

    public final Context getContext() {
        return this.mContext;
    }

    public final Looper getLooper() {
        return this.zzWt;
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public void getRemoteService(IAccountAccessor authedAccountAccessor, Set<Scope> scopes) {
        try {
            GetServiceRequest zzf2 = new GetServiceRequest(this.zzaat).zzcb(this.mContext.getPackageName()).zzf(zzkR());
            if (scopes != null) {
                zzf2.zzb(scopes);
            }
            if (requiresSignIn()) {
                zzf2.zzb(zznt()).zzb(authedAccountAccessor);
            } else if (requiresAccount()) {
                zzf2.zzb(this.zzMY);
            }
            this.zzaal.zza(new zzd(this, this.zzaau.get()), zzf2);
        } catch (DeadObjectException e) {
            Log.w("GmsClient", "service died");
            zzbs(1);
        } catch (RemoteException e2) {
            Log.w("GmsClient", "Remote exception occurred", e2);
        }
    }

    protected abstract String getServiceDescriptor();

    protected abstract String getStartServiceAction();

    @Override // com.google.android.gms.common.api.Api.Client, com.google.android.gms.common.internal.zzj.zza
    public boolean isConnected() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzaaq == 3;
        }
        return z;
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public boolean isConnecting() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzaaq == 2;
        }
        return z;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void onConnectionFailed(ConnectionResult result) {
    }

    protected void onConnectionSuspended(int cause) {
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public boolean requiresAccount() {
        return false;
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public boolean requiresSignIn() {
        return false;
    }

    @Override // com.google.android.gms.common.api.Api.Client
    public void validateAccount(IAccountAccessor resolvedAccountAccessor) {
        try {
            this.zzaal.zza(new zzd(this, this.zzaau.get()), new ValidateAccountRequest(resolvedAccountAccessor, (Scope[]) this.zzWJ.toArray(new Scope[this.zzWJ.size()]), this.mContext.getPackageName(), zznN()));
        } catch (DeadObjectException e) {
            Log.w("GmsClient", "service died");
            zzbs(1);
        } catch (RemoteException e2) {
            Log.w("GmsClient", "Remote exception occurred", e2);
        }
    }

    protected abstract T zzT(IBinder iBinder);

    protected Set<Scope> zza(Set<Scope> set) {
        return set;
    }

    protected void zza(int i, Bundle bundle, int i2) {
        this.mHandler.sendMessage(this.mHandler.obtainMessage(5, i2, -1, new C0037zzi(i, bundle)));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zza(int i, IBinder iBinder, Bundle bundle, int i2) {
        this.mHandler.sendMessage(this.mHandler.obtainMessage(1, i2, -1, new zzg(i, iBinder, bundle)));
    }

    @Deprecated
    public final void zza(zzi<T>.zzc<?> zzcVar) {
        synchronized (this.zzaao) {
            this.zzaao.add(zzcVar);
        }
        this.mHandler.sendMessage(this.mHandler.obtainMessage(2, this.zzaau.get(), -1, zzcVar));
    }

    public void zzbs(int i) {
        this.mHandler.sendMessage(this.mHandler.obtainMessage(4, this.zzaau.get(), i));
    }

    protected void zzbt(int i) {
        this.mHandler.sendMessage(this.mHandler.obtainMessage(6, i, -1, new zzh()));
    }

    protected String zzkQ() {
        return this.zzXa.zznz();
    }

    protected Bundle zzkR() {
        return new Bundle();
    }

    public Bundle zzlM() {
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zznG() {
    }

    public void zznJ() {
        int isGooglePlayServicesAvailable = GooglePlayServicesUtil.isGooglePlayServicesAvailable(this.mContext);
        if (isGooglePlayServicesAvailable == 0) {
            connect(new zzf());
            return;
        }
        zza(1, (int) null);
        this.zzaam = new zzf();
        this.mHandler.sendMessage(this.mHandler.obtainMessage(3, this.zzaau.get(), isGooglePlayServicesAvailable));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final com.google.android.gms.common.internal.zze zznK() {
        return this.zzXa;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public final void zznL() {
        if (!isConnected()) {
            throw new IllegalStateException("Not connected. Call connect() and wait for onConnected() to be called.");
        }
    }

    public final T zznM() throws DeadObjectException {
        T t;
        synchronized (this.zzqt) {
            if (this.zzaaq == 4) {
                throw new DeadObjectException();
            }
            zznL();
            zzu.zza(this.zzaan != null, "Client is connected but service is null");
            t = this.zzaan;
        }
        return t;
    }

    protected Bundle zznN() {
        return null;
    }

    public final Account zznt() {
        return this.zzMY != null ? this.zzMY : new Account("<<default account>>", GoogleAuthUtil.GOOGLE_ACCOUNT_TYPE);
    }
}
