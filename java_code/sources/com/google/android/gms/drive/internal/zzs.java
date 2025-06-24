package com.google.android.gms.drive.internal;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.content.pm.ServiceInfo;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.PendingResult;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.drive.DriveId;
import com.google.android.gms.drive.events.ChangeListener;
import com.google.android.gms.drive.events.ChangesAvailableOptions;
import com.google.android.gms.drive.events.DriveEventService;
import com.google.android.gms.drive.internal.zzak;
import com.google.android.gms.drive.internal.zzq;
import com.google.android.gms.drive.internal.zzr;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public class zzs extends com.google.android.gms.common.internal.zzi<zzak> {
    private final String zzOe;
    final GoogleApiClient.ConnectionCallbacks zzaar;
    private final Bundle zzaeM;
    private final boolean zzaeN;
    private DriveId zzaeO;
    private DriveId zzaeP;
    final Map<DriveId, Map<ChangeListener, zzac>> zzaeQ;
    final Map<com.google.android.gms.drive.events.zzc, zzac> zzaeR;
    final Map<DriveId, Map<com.google.android.gms.drive.events.zzi, zzac>> zzaeS;
    final Map<DriveId, Map<com.google.android.gms.drive.events.zzi, zzac>> zzaeT;

    public zzs(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, Bundle bundle) {
        super(context, looper, 11, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzaeQ = new HashMap();
        this.zzaeR = new HashMap();
        this.zzaeS = new HashMap();
        this.zzaeT = new HashMap();
        this.zzOe = zzeVar.zzny();
        this.zzaar = connectionCallbacks;
        this.zzaeM = bundle;
        Intent intent = new Intent(DriveEventService.ACTION_HANDLE_EVENT);
        intent.setPackage(context.getPackageName());
        List<ResolveInfo> queryIntentServices = context.getPackageManager().queryIntentServices(intent, 0);
        switch (queryIntentServices.size()) {
            case 0:
                this.zzaeN = false;
                return;
            case 1:
                ServiceInfo serviceInfo = queryIntentServices.get(0).serviceInfo;
                if (!serviceInfo.exported) {
                    throw new IllegalStateException("Drive event service " + serviceInfo.name + " must be exported in AndroidManifest.xml");
                }
                this.zzaeN = true;
                return;
            default:
                throw new IllegalStateException("AndroidManifest.xml can only define one service that handles the " + intent.getAction() + " action");
        }
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, final int i, final DriveId driveId) {
        com.google.android.gms.common.internal.zzu.zzb(com.google.android.gms.drive.events.zzg.zza(i, driveId), "id");
        com.google.android.gms.common.internal.zzu.zza(isConnected(), "Client must be connected");
        return googleApiClient.zzb(new zzr.zza(googleApiClient) { // from class: com.google.android.gms.drive.internal.zzs.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new RemoveEventListenerRequest(driveId, i), (zzam) null, (String) null, new zzbq(this));
            }
        });
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, final int i, final DriveId driveId, final ChangesAvailableOptions changesAvailableOptions) {
        com.google.android.gms.common.internal.zzu.zzb(com.google.android.gms.drive.events.zzg.zza(i, driveId), "id");
        com.google.android.gms.common.internal.zzu.zza(isConnected(), "Client must be connected");
        if (this.zzaeN) {
            return googleApiClient.zzb(new zzr.zza(googleApiClient) { // from class: com.google.android.gms.drive.internal.zzs.3
                /* JADX INFO: Access modifiers changed from: protected */
                @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
                public void zza(zzs zzsVar) throws RemoteException {
                    zzsVar.zzpB().zza(new AddEventListenerRequest(driveId, i, changesAvailableOptions), (zzam) null, (String) null, new zzbq(this));
                }
            });
        }
        throw new IllegalStateException("Application must define an exported DriveEventService subclass in AndroidManifest.xml to add event subscriptions");
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, final int i, final DriveId driveId, final zzac zzacVar) {
        return googleApiClient.zzb(new zzr.zza(googleApiClient) { // from class: com.google.android.gms.drive.internal.zzs.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new RemoveEventListenerRequest(driveId, i), zzacVar, (String) null, new zzbq(this));
            }
        });
    }

    private PendingResult<Status> zza(GoogleApiClient googleApiClient, final int i, final DriveId driveId, final zzac zzacVar, final ChangesAvailableOptions changesAvailableOptions) {
        return googleApiClient.zzb(new zzr.zza(googleApiClient) { // from class: com.google.android.gms.drive.internal.zzs.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new AddEventListenerRequest(driveId, i, changesAvailableOptions), zzacVar, (String) null, new zzbq(this));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PendingResult<Status> cancelPendingActions(GoogleApiClient apiClient, final List<String> pendingTags) {
        com.google.android.gms.common.internal.zzu.zzV(pendingTags != null);
        com.google.android.gms.common.internal.zzu.zzV(pendingTags.isEmpty() ? false : true);
        com.google.android.gms.common.internal.zzu.zza(isConnected(), "Client must be connected");
        return apiClient.zzb(new zzr.zza(apiClient) { // from class: com.google.android.gms.drive.internal.zzs.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.common.api.zza.AbstractC0032zza
            public void zza(zzs zzsVar) throws RemoteException {
                zzsVar.zzpB().zza(new CancelPendingActionsRequest(pendingTags), new zzbq(this));
            }
        });
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public void disconnect() {
        if (isConnected()) {
            try {
                zznM().zza(new DisconnectRequest());
            } catch (RemoteException e) {
            }
        }
        super.disconnect();
        synchronized (this.zzaeQ) {
            this.zzaeQ.clear();
        }
        synchronized (this.zzaeR) {
            this.zzaeR.clear();
        }
        synchronized (this.zzaeS) {
            this.zzaeS.clear();
        }
        synchronized (this.zzaeT) {
            this.zzaeT.clear();
        }
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.drive.internal.IDriveService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.drive.ApiService.START";
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresSignIn() {
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PendingResult<Status> zza(GoogleApiClient googleApiClient, DriveId driveId) {
        return zza(googleApiClient, 1, driveId, (ChangesAvailableOptions) null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PendingResult<Status> zza(GoogleApiClient googleApiClient, DriveId driveId, ChangeListener changeListener) {
        HashMap hashMap;
        zzac zzacVar;
        PendingResult<Status> zzjVar;
        com.google.android.gms.common.internal.zzu.zzb(com.google.android.gms.drive.events.zzg.zza(1, driveId), "id");
        com.google.android.gms.common.internal.zzu.zzb(changeListener, "listener");
        com.google.android.gms.common.internal.zzu.zza(isConnected(), "Client must be connected");
        synchronized (this.zzaeQ) {
            Map<ChangeListener, zzac> map = this.zzaeQ.get(driveId);
            if (map == null) {
                HashMap hashMap2 = new HashMap();
                this.zzaeQ.put(driveId, hashMap2);
                hashMap = hashMap2;
            } else {
                hashMap = map;
            }
            zzac zzacVar2 = hashMap.get(changeListener);
            if (zzacVar2 == null) {
                zzacVar = new zzac(getLooper(), getContext(), 1, changeListener);
                hashMap.put(changeListener, zzacVar);
            } else if (zzacVar2.zzcB(1)) {
                zzjVar = new zzq.zzj(googleApiClient, Status.zzXP);
            } else {
                zzacVar = zzacVar2;
            }
            zzacVar.zzcA(1);
            zzjVar = zza(googleApiClient, 1, driveId, zzacVar, null);
        }
        return zzjVar;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    public void zza(int i, IBinder iBinder, Bundle bundle, int i2) {
        if (bundle != null) {
            bundle.setClassLoader(getClass().getClassLoader());
            this.zzaeO = (DriveId) bundle.getParcelable("com.google.android.gms.drive.root_id");
            this.zzaeP = (DriveId) bundle.getParcelable("com.google.android.gms.drive.appdata_id");
        }
        super.zza(i, iBinder, bundle, i2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzaN */
    public zzak zzT(IBinder iBinder) {
        return zzak.zza.zzaO(iBinder);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PendingResult<Status> zzb(GoogleApiClient googleApiClient, DriveId driveId) {
        return zza(googleApiClient, 1, driveId);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public PendingResult<Status> zzb(GoogleApiClient googleApiClient, DriveId driveId, ChangeListener changeListener) {
        PendingResult<Status> zza;
        com.google.android.gms.common.internal.zzu.zzb(com.google.android.gms.drive.events.zzg.zza(1, driveId), "id");
        com.google.android.gms.common.internal.zzu.zza(isConnected(), "Client must be connected");
        com.google.android.gms.common.internal.zzu.zzb(changeListener, "listener");
        synchronized (this.zzaeQ) {
            Map<ChangeListener, zzac> map = this.zzaeQ.get(driveId);
            if (map == null) {
                zza = new zzq.zzj(googleApiClient, Status.zzXP);
            } else {
                zzac remove = map.remove(changeListener);
                if (remove == null) {
                    zza = new zzq.zzj(googleApiClient, Status.zzXP);
                } else {
                    if (map.isEmpty()) {
                        this.zzaeQ.remove(driveId);
                    }
                    zza = zza(googleApiClient, 1, driveId, remove);
                }
            }
        }
        return zza;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zzkR() {
        String packageName = getContext().getPackageName();
        com.google.android.gms.common.internal.zzu.zzu(packageName);
        com.google.android.gms.common.internal.zzu.zzU(!zznK().zznw().isEmpty());
        Bundle bundle = new Bundle();
        if (!packageName.equals(this.zzOe)) {
            bundle.putString("proxy_package_name", this.zzOe);
        }
        bundle.putAll(this.zzaeM);
        return bundle;
    }

    public zzak zzpB() throws DeadObjectException {
        return zznM();
    }

    public DriveId zzpC() {
        return this.zzaeO;
    }

    public DriveId zzpD() {
        return this.zzaeP;
    }

    public boolean zzpE() {
        return this.zzaeN;
    }
}
