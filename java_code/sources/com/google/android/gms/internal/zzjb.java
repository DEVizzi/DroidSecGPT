package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import android.util.Log;
import com.google.android.gms.appstate.AppStateBuffer;
import com.google.android.gms.appstate.AppStateManager;
import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.internal.zzjd;
import java.util.Set;
/* loaded from: classes.dex */
public final class zzjb extends com.google.android.gms.common.internal.zzi<zzjd> {

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zza extends zzja {
        private final zza.zzb<AppStateManager.StateDeletedResult> zzOs;

        public zza(zza.zzb<AppStateManager.StateDeletedResult> zzbVar) {
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzb(zzbVar, "Result holder must not be null");
        }

        @Override // com.google.android.gms.internal.zzja, com.google.android.gms.internal.zzjc
        public void zzg(int i, int i2) {
            this.zzOs.zzm(new zzb(new Status(i), i2));
        }
    }

    /* loaded from: classes.dex */
    private static final class zzb implements AppStateManager.StateDeletedResult {
        private final Status zzOt;
        private final int zzOu;

        public zzb(Status status, int i) {
            this.zzOt = status;
            this.zzOu = i;
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateDeletedResult
        public int getStateKey() {
            return this.zzOu;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zzc extends zzja {
        private final zza.zzb<AppStateManager.StateListResult> zzOs;

        public zzc(zza.zzb<AppStateManager.StateListResult> zzbVar) {
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzb(zzbVar, "Result holder must not be null");
        }

        @Override // com.google.android.gms.internal.zzja, com.google.android.gms.internal.zzjc
        public void zza(DataHolder dataHolder) {
            this.zzOs.zzm(new zzd(dataHolder));
        }
    }

    /* loaded from: classes.dex */
    private static final class zzd extends com.google.android.gms.common.api.zzc implements AppStateManager.StateListResult {
        private final AppStateBuffer zzOv;

        public zzd(DataHolder dataHolder) {
            super(dataHolder);
            this.zzOv = new AppStateBuffer(dataHolder);
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateListResult
        public AppStateBuffer getStateBuffer() {
            return this.zzOv;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zze extends zzja {
        private final zza.zzb<AppStateManager.StateResult> zzOs;

        public zze(zza.zzb<AppStateManager.StateResult> zzbVar) {
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzb(zzbVar, "Result holder must not be null");
        }

        @Override // com.google.android.gms.internal.zzja, com.google.android.gms.internal.zzjc
        public void zza(int i, DataHolder dataHolder) {
            this.zzOs.zzm(new zzf(i, dataHolder));
        }
    }

    /* loaded from: classes.dex */
    private static final class zzf extends com.google.android.gms.common.api.zzc implements AppStateManager.StateConflictResult, AppStateManager.StateLoadedResult, AppStateManager.StateResult {
        private final int zzOu;
        private final AppStateBuffer zzOv;

        public zzf(int i, DataHolder dataHolder) {
            super(dataHolder);
            this.zzOu = i;
            this.zzOv = new AppStateBuffer(dataHolder);
        }

        private boolean zzkX() {
            return this.zzOt.getStatusCode() == 2000;
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateResult
        public AppStateManager.StateConflictResult getConflictResult() {
            if (zzkX()) {
                return this;
            }
            return null;
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateResult
        public AppStateManager.StateLoadedResult getLoadedResult() {
            if (zzkX()) {
                return null;
            }
            return this;
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateConflictResult, com.google.android.gms.appstate.AppStateManager.StateLoadedResult
        public byte[] getLocalData() {
            if (this.zzOv.getCount() == 0) {
                return null;
            }
            return this.zzOv.get(0).getLocalData();
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateConflictResult
        public String getResolvedVersion() {
            if (this.zzOv.getCount() == 0) {
                return null;
            }
            return this.zzOv.get(0).getConflictVersion();
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateConflictResult
        public byte[] getServerData() {
            if (this.zzOv.getCount() == 0) {
                return null;
            }
            return this.zzOv.get(0).getConflictData();
        }

        @Override // com.google.android.gms.appstate.AppStateManager.StateConflictResult, com.google.android.gms.appstate.AppStateManager.StateLoadedResult
        public int getStateKey() {
            return this.zzOu;
        }

        @Override // com.google.android.gms.common.api.zzc, com.google.android.gms.common.api.Releasable
        public void release() {
            this.zzOv.release();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public static final class zzg extends zzja {
        private final zza.zzb<Status> zzOs;

        public zzg(zza.zzb<Status> zzbVar) {
            this.zzOs = (zza.zzb) com.google.android.gms.common.internal.zzu.zzb(zzbVar, "Holder must not be null");
        }

        @Override // com.google.android.gms.internal.zzja, com.google.android.gms.internal.zzjc
        public void zzkU() {
            this.zzOs.zzm(new Status(0));
        }
    }

    public zzjb(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 7, connectionCallbacks, onConnectionFailedListener, zzeVar);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.appstate.internal.IAppStateService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.appstate.service.START";
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresSignIn() {
        return true;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Set<Scope> zza(Set<Scope> set) {
        com.google.android.gms.common.internal.zzu.zza(set.contains(new Scope(Scopes.APP_STATE)), String.format("App State APIs requires %s to function.", Scopes.APP_STATE));
        return set;
    }

    public void zza(zza.zzb<AppStateManager.StateListResult> zzbVar) throws RemoteException {
        zznM().zza(new zzc(zzbVar));
    }

    public void zza(zza.zzb<AppStateManager.StateDeletedResult> zzbVar, int i) throws RemoteException {
        zznM().zzb(new zza(zzbVar), i);
    }

    public void zza(zza.zzb<AppStateManager.StateResult> zzbVar, int i, String str, byte[] bArr) throws RemoteException {
        zznM().zza(new zze(zzbVar), i, str, bArr);
    }

    public void zza(zza.zzb<AppStateManager.StateResult> zzbVar, int i, byte[] bArr) throws RemoteException {
        zznM().zza(zzbVar == null ? null : new zze(zzbVar), i, bArr);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzaj */
    public zzjd zzT(IBinder iBinder) {
        return zzjd.zza.zzal(iBinder);
    }

    public void zzb(zza.zzb<Status> zzbVar) throws RemoteException {
        zznM().zzb(new zzg(zzbVar));
    }

    public void zzb(zza.zzb<AppStateManager.StateResult> zzbVar, int i) throws RemoteException {
        zznM().zza(new zze(zzbVar), i);
    }

    public int zzkV() {
        try {
            return zznM().zzkV();
        } catch (RemoteException e) {
            Log.w("AppStateClient", "service died");
            return 2;
        }
    }

    public int zzkW() {
        try {
            return zznM().zzkW();
        } catch (RemoteException e) {
            Log.w("AppStateClient", "service died");
            return 2;
        }
    }
}
