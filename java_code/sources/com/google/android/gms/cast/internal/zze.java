package com.google.android.gms.cast.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.cast.ApplicationMetadata;
import com.google.android.gms.cast.Cast;
import com.google.android.gms.cast.CastDevice;
import com.google.android.gms.cast.LaunchOptions;
import com.google.android.gms.cast.internal.zzi;
import com.google.android.gms.cast.internal.zzj;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.internal.BinderWrapper;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
/* loaded from: classes.dex */
public final class zze extends com.google.android.gms.common.internal.zzi<zzi> {
    private static final zzl zzQW = new zzl("CastClientImpl");
    private static final Object zzUD = new Object();
    private static final Object zzUE = new Object();
    private final Cast.Listener zzQI;
    private double zzSh;
    private boolean zzSi;
    private final Map<Long, zza.zzb<Status>> zzUA;
    private zza.zzb<Cast.ApplicationConnectionResult> zzUB;
    private zza.zzb<Status> zzUC;
    private ApplicationMetadata zzUl;
    private final CastDevice zzUm;
    private final Map<String, Cast.MessageReceivedCallback> zzUn;
    private final long zzUo;
    private zzb zzUp;
    private String zzUq;
    private boolean zzUr;
    private boolean zzUs;
    private boolean zzUt;
    private int zzUu;
    private int zzUv;
    private final AtomicLong zzUw;
    private String zzUx;
    private String zzUy;
    private Bundle zzUz;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zza implements Cast.ApplicationConnectionResult {
        private final String zzFE;
        private final Status zzOt;
        private final ApplicationMetadata zzUF;
        private final String zzUG;
        private final boolean zzUH;

        public zza(Status status) {
            this(status, null, null, null, false);
        }

        public zza(Status status, ApplicationMetadata applicationMetadata, String str, String str2, boolean z) {
            this.zzOt = status;
            this.zzUF = applicationMetadata;
            this.zzUG = str;
            this.zzFE = str2;
            this.zzUH = z;
        }

        @Override // com.google.android.gms.cast.Cast.ApplicationConnectionResult
        public ApplicationMetadata getApplicationMetadata() {
            return this.zzUF;
        }

        @Override // com.google.android.gms.cast.Cast.ApplicationConnectionResult
        public String getApplicationStatus() {
            return this.zzUG;
        }

        @Override // com.google.android.gms.cast.Cast.ApplicationConnectionResult
        public String getSessionId() {
            return this.zzFE;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.cast.Cast.ApplicationConnectionResult
        public boolean getWasLaunched() {
            return this.zzUH;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static class zzb extends zzj.zza {
        private final Handler mHandler;
        private final AtomicReference<zze> zzUI;

        public zzb(zze zzeVar) {
            this.zzUI = new AtomicReference<>(zzeVar);
            this.mHandler = new Handler(zzeVar.getLooper());
        }

        private void zza(zze zzeVar, long j, int i) {
            zza.zzb zzbVar;
            synchronized (zzeVar.zzUA) {
                zzbVar = (zza.zzb) zzeVar.zzUA.remove(Long.valueOf(j));
            }
            if (zzbVar != null) {
                zzbVar.zzm(new Status(i));
            }
        }

        private boolean zza(zze zzeVar, int i) {
            synchronized (zze.zzUE) {
                if (zzeVar.zzUC != null) {
                    zzeVar.zzUC.zzm(new Status(i));
                    zzeVar.zzUC = null;
                    return true;
                }
                return false;
            }
        }

        public boolean isDisposed() {
            return this.zzUI.get() == null;
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void onApplicationDisconnected(final int statusCode) {
            final zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zzeVar.zzUx = null;
            zzeVar.zzUy = null;
            zza(zzeVar, statusCode);
            if (zzeVar.zzQI != null) {
                this.mHandler.post(new Runnable() { // from class: com.google.android.gms.cast.internal.zze.zzb.1
                    @Override // java.lang.Runnable
                    public void run() {
                        if (zzeVar.zzQI != null) {
                            zzeVar.zzQI.onApplicationDisconnected(statusCode);
                        }
                    }
                });
            }
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zza(ApplicationMetadata applicationMetadata, String str, String str2, boolean z) {
            zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zzeVar.zzUl = applicationMetadata;
            zzeVar.zzUx = applicationMetadata.getApplicationId();
            zzeVar.zzUy = str2;
            synchronized (zze.zzUD) {
                if (zzeVar.zzUB != null) {
                    zzeVar.zzUB.zzm(new zza(new Status(0), applicationMetadata, str, str2, z));
                    zzeVar.zzUB = null;
                }
            }
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zza(String str, double d, boolean z) {
            zze.zzQW.zzb("Deprecated callback: \"onStatusreceived\"", new Object[0]);
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zza(String str, long j, int i) {
            zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zza(zzeVar, j, i);
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzaM(int i) {
            zze zzlW = zzlW();
            if (zzlW == null) {
                return;
            }
            zze.zzQW.zzb("ICastDeviceControllerListener.onDisconnected: %d", Integer.valueOf(i));
            if (i != 0) {
                zzlW.zzbs(2);
            }
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzaN(int i) {
            zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            synchronized (zze.zzUD) {
                if (zzeVar.zzUB != null) {
                    zzeVar.zzUB.zzm(new zza(new Status(i)));
                    zzeVar.zzUB = null;
                }
            }
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzaO(int i) {
            zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zza(zzeVar, i);
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzaP(int i) {
            zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zza(zzeVar, i);
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzb(final ApplicationStatus applicationStatus) {
            final zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zze.zzQW.zzb("onApplicationStatusChanged", new Object[0]);
            this.mHandler.post(new Runnable() { // from class: com.google.android.gms.cast.internal.zze.zzb.3
                @Override // java.lang.Runnable
                public void run() {
                    zzeVar.zza(applicationStatus);
                }
            });
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzb(final DeviceStatus deviceStatus) {
            final zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zze.zzQW.zzb("onDeviceStatusChanged", new Object[0]);
            this.mHandler.post(new Runnable() { // from class: com.google.android.gms.cast.internal.zze.zzb.2
                @Override // java.lang.Runnable
                public void run() {
                    zzeVar.zza(deviceStatus);
                }
            });
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzb(String str, byte[] bArr) {
            if (this.zzUI.get() == null) {
                return;
            }
            zze.zzQW.zzb("IGNORING: Receive (type=binary, ns=%s) <%d bytes>", str, Integer.valueOf(bArr.length));
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzd(String str, long j) {
            zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zza(zzeVar, j, 0);
        }

        public zze zzlW() {
            zze andSet = this.zzUI.getAndSet(null);
            if (andSet == null) {
                return null;
            }
            andSet.zzlL();
            return andSet;
        }

        @Override // com.google.android.gms.cast.internal.zzj
        public void zzq(final String str, final String str2) {
            final zze zzeVar = this.zzUI.get();
            if (zzeVar == null) {
                return;
            }
            zze.zzQW.zzb("Receive (type=text, ns=%s) %s", str, str2);
            this.mHandler.post(new Runnable() { // from class: com.google.android.gms.cast.internal.zze.zzb.4
                @Override // java.lang.Runnable
                public void run() {
                    Cast.MessageReceivedCallback messageReceivedCallback;
                    synchronized (zzeVar.zzUn) {
                        messageReceivedCallback = (Cast.MessageReceivedCallback) zzeVar.zzUn.get(str);
                    }
                    if (messageReceivedCallback != null) {
                        messageReceivedCallback.onMessageReceived(zzeVar.zzUm, str, str2);
                    } else {
                        zze.zzQW.zzb("Discarded message for unknown namespace '%s'", str);
                    }
                }
            });
        }
    }

    public zze(Context context, Looper looper, CastDevice castDevice, long j, Cast.Listener listener, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 10, connectionCallbacks, onConnectionFailedListener);
        this.zzUm = castDevice;
        this.zzQI = listener;
        this.zzUo = j;
        this.zzUn = new HashMap();
        this.zzUw = new AtomicLong(0L);
        this.zzUA = new HashMap();
        zzlL();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zza(ApplicationStatus applicationStatus) {
        boolean z;
        String zzlI = applicationStatus.zzlI();
        if (zzf.zza(zzlI, this.zzUq)) {
            z = false;
        } else {
            this.zzUq = zzlI;
            z = true;
        }
        zzQW.zzb("hasChanged=%b, mFirstApplicationStatusUpdate=%b", Boolean.valueOf(z), Boolean.valueOf(this.zzUr));
        if (this.zzQI != null && (z || this.zzUr)) {
            this.zzQI.onApplicationStatusChanged();
        }
        this.zzUr = false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zza(DeviceStatus deviceStatus) {
        boolean z;
        boolean z2;
        boolean z3;
        ApplicationMetadata applicationMetadata = deviceStatus.getApplicationMetadata();
        if (!zzf.zza(applicationMetadata, this.zzUl)) {
            this.zzUl = applicationMetadata;
            this.zzQI.onApplicationMetadataChanged(this.zzUl);
        }
        double zzlO = deviceStatus.zzlO();
        if (zzlO == Double.NaN || Math.abs(zzlO - this.zzSh) <= 1.0E-7d) {
            z = false;
        } else {
            this.zzSh = zzlO;
            z = true;
        }
        boolean zzlX = deviceStatus.zzlX();
        if (zzlX != this.zzSi) {
            this.zzSi = zzlX;
            z = true;
        }
        zzQW.zzb("hasVolumeChanged=%b, mFirstDeviceStatusUpdate=%b", Boolean.valueOf(z), Boolean.valueOf(this.zzUs));
        if (this.zzQI != null && (z || this.zzUs)) {
            this.zzQI.onVolumeChanged();
        }
        int zzlP = deviceStatus.zzlP();
        if (zzlP != this.zzUu) {
            this.zzUu = zzlP;
            z2 = true;
        } else {
            z2 = false;
        }
        zzQW.zzb("hasActiveInputChanged=%b, mFirstDeviceStatusUpdate=%b", Boolean.valueOf(z2), Boolean.valueOf(this.zzUs));
        if (this.zzQI != null && (z2 || this.zzUs)) {
            this.zzQI.onActiveInputStateChanged(this.zzUu);
        }
        int zzlQ = deviceStatus.zzlQ();
        if (zzlQ != this.zzUv) {
            this.zzUv = zzlQ;
            z3 = true;
        } else {
            z3 = false;
        }
        zzQW.zzb("hasStandbyStateChanged=%b, mFirstDeviceStatusUpdate=%b", Boolean.valueOf(z3), Boolean.valueOf(this.zzUs));
        if (this.zzQI != null && (z3 || this.zzUs)) {
            this.zzQI.onStandbyStateChanged(this.zzUv);
        }
        this.zzUs = false;
    }

    private void zzc(zza.zzb<Cast.ApplicationConnectionResult> zzbVar) {
        synchronized (zzUD) {
            if (this.zzUB != null) {
                this.zzUB.zzm(new zza(new Status(2002)));
            }
            this.zzUB = zzbVar;
        }
    }

    private void zze(zza.zzb<Status> zzbVar) {
        synchronized (zzUE) {
            if (this.zzUC != null) {
                zzbVar.zzm(new Status(2001));
            } else {
                this.zzUC = zzbVar;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzlL() {
        this.zzUt = false;
        this.zzUu = -1;
        this.zzUv = -1;
        this.zzUl = null;
        this.zzUq = null;
        this.zzSh = 0.0d;
        this.zzSi = false;
    }

    private void zzlR() {
        zzQW.zzb("removing all MessageReceivedCallbacks", new Object[0]);
        synchronized (this.zzUn) {
            this.zzUn.clear();
        }
    }

    private void zzlS() throws IllegalStateException {
        if (!this.zzUt || this.zzUp == null || this.zzUp.isDisposed()) {
            throw new IllegalStateException("Not connected to a device");
        }
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        zzQW.zzb("disconnect(); ServiceListener=%s, isConnected=%b", this.zzUp, Boolean.valueOf(isConnected()));
        zzb zzbVar = this.zzUp;
        this.zzUp = null;
        if (zzbVar == null || zzbVar.zzlW() == null) {
            zzQW.zzb("already disposed, so short-circuiting", new Object[0]);
            return;
        }
        zzlR();
        try {
            if (isConnected() || isConnecting()) {
                zznM().disconnect();
            }
        } catch (RemoteException e) {
            zzQW.zzb(e, "Error while disconnecting the controller interface: %s", e.getMessage());
        } finally {
            super.disconnect();
        }
    }

    public ApplicationMetadata getApplicationMetadata() throws IllegalStateException {
        zzlS();
        return this.zzUl;
    }

    public String getApplicationStatus() throws IllegalStateException {
        zzlS();
        return this.zzUq;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.cast.internal.ICastDeviceController";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.cast.service.BIND_CAST_DEVICE_CONTROLLER_SERVICE";
    }

    public boolean isMute() throws IllegalStateException {
        zzlS();
        return this.zzSi;
    }

    @Override // com.google.android.gms.common.internal.zzi
    public void onConnectionFailed(ConnectionResult result) {
        super.onConnectionFailed(result);
        zzlR();
    }

    public void zzR(boolean z) throws IllegalStateException, RemoteException {
        zznM().zza(z, this.zzSh, this.zzSi);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    public void zza(int i, IBinder iBinder, Bundle bundle, int i2) {
        zzQW.zzb("in onPostInitHandler; statusCode=%d", Integer.valueOf(i));
        if (i == 0 || i == 1001) {
            this.zzUt = true;
            this.zzUr = true;
            this.zzUs = true;
        } else {
            this.zzUt = false;
        }
        if (i == 1001) {
            this.zzUz = new Bundle();
            this.zzUz.putBoolean(Cast.EXTRA_APP_NO_LONGER_RUNNING, true);
            i = 0;
        }
        super.zza(i, iBinder, bundle, i2);
    }

    public void zza(String str, Cast.MessageReceivedCallback messageReceivedCallback) throws IllegalArgumentException, IllegalStateException, RemoteException {
        zzf.zzbD(str);
        zzbC(str);
        if (messageReceivedCallback != null) {
            synchronized (this.zzUn) {
                this.zzUn.put(str, messageReceivedCallback);
            }
            zznM().zzbH(str);
        }
    }

    public void zza(String str, LaunchOptions launchOptions, zza.zzb<Cast.ApplicationConnectionResult> zzbVar) throws IllegalStateException, RemoteException {
        zzc(zzbVar);
        zznM().zza(str, launchOptions);
    }

    public void zza(String str, zza.zzb<Status> zzbVar) throws IllegalStateException, RemoteException {
        zze(zzbVar);
        zznM().zzbG(str);
    }

    public void zza(String str, String str2, zza.zzb<Status> zzbVar) throws IllegalArgumentException, IllegalStateException, RemoteException {
        if (TextUtils.isEmpty(str2)) {
            throw new IllegalArgumentException("The message payload cannot be null or empty");
        }
        if (str2.length() > 65536) {
            throw new IllegalArgumentException("Message exceeds maximum size");
        }
        zzf.zzbD(str);
        zzlS();
        long incrementAndGet = this.zzUw.incrementAndGet();
        try {
            this.zzUA.put(Long.valueOf(incrementAndGet), zzbVar);
            zznM().zza(str, str2, incrementAndGet);
        } catch (Throwable th) {
            this.zzUA.remove(Long.valueOf(incrementAndGet));
            throw th;
        }
    }

    public void zza(String str, boolean z, zza.zzb<Cast.ApplicationConnectionResult> zzbVar) throws IllegalStateException, RemoteException {
        zzc(zzbVar);
        zznM().zzf(str, z);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzaw */
    public zzi zzT(IBinder iBinder) {
        return zzi.zza.zzax(iBinder);
    }

    public void zzb(String str, String str2, zza.zzb<Cast.ApplicationConnectionResult> zzbVar) throws IllegalStateException, RemoteException {
        zzc(zzbVar);
        zznM().zzr(str, str2);
    }

    public void zzbC(String str) throws IllegalArgumentException, RemoteException {
        Cast.MessageReceivedCallback remove;
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("Channel namespace cannot be null or empty");
        }
        synchronized (this.zzUn) {
            remove = this.zzUn.remove(str);
        }
        if (remove != null) {
            try {
                zznM().zzbI(str);
            } catch (IllegalStateException e) {
                zzQW.zzb(e, "Error unregistering namespace (%s): %s", str, e.getMessage());
            }
        }
    }

    public void zzd(double d) throws IllegalArgumentException, IllegalStateException, RemoteException {
        if (Double.isInfinite(d) || Double.isNaN(d)) {
            throw new IllegalArgumentException("Volume cannot be " + d);
        }
        zznM().zza(d, this.zzSh, this.zzSi);
    }

    public void zzd(zza.zzb<Status> zzbVar) throws IllegalStateException, RemoteException {
        zze(zzbVar);
        zznM().zzlY();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zzkR() {
        Bundle bundle = new Bundle();
        zzQW.zzb("getRemoteService(): mLastApplicationId=%s, mLastSessionId=%s", this.zzUx, this.zzUy);
        this.zzUm.putInBundle(bundle);
        bundle.putLong("com.google.android.gms.cast.EXTRA_CAST_FLAGS", this.zzUo);
        this.zzUp = new zzb(this);
        bundle.putParcelable("listener", new BinderWrapper(this.zzUp.asBinder()));
        if (this.zzUx != null) {
            bundle.putString("last_application_id", this.zzUx);
            if (this.zzUy != null) {
                bundle.putString("last_session_id", this.zzUy);
            }
        }
        return bundle;
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.internal.zzj.zza
    public Bundle zzlM() {
        if (this.zzUz != null) {
            Bundle bundle = this.zzUz;
            this.zzUz = null;
            return bundle;
        }
        return super.zzlM();
    }

    public void zzlN() throws IllegalStateException, RemoteException {
        zznM().zzlN();
    }

    public double zzlO() throws IllegalStateException {
        zzlS();
        return this.zzSh;
    }

    public int zzlP() throws IllegalStateException {
        zzlS();
        return this.zzUu;
    }

    public int zzlQ() throws IllegalStateException {
        zzlS();
        return this.zzUv;
    }
}
