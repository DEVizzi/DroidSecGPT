package com.google.android.gms.plus.internal;

import android.app.PendingIntent;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.IBinder;
import android.os.Looper;
import android.os.RemoteException;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.data.DataHolder;
import com.google.android.gms.common.internal.ICancelToken;
import com.google.android.gms.common.internal.zzi;
import com.google.android.gms.common.server.response.SafeParcelResponse;
import com.google.android.gms.plus.Moments;
import com.google.android.gms.plus.People;
import com.google.android.gms.plus.Plus;
import com.google.android.gms.plus.internal.model.moments.MomentEntity;
import com.google.android.gms.plus.internal.model.people.PersonEntity;
import com.google.android.gms.plus.internal.zzd;
import com.google.android.gms.plus.model.moments.Moment;
import com.google.android.gms.plus.model.moments.MomentBuffer;
import com.google.android.gms.plus.model.people.Person;
import com.google.android.gms.plus.model.people.PersonBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
/* loaded from: classes.dex */
public class zze extends zzi<com.google.android.gms.plus.internal.zzd> {
    private Person zzaHl;
    private final PlusSession zzaHm;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zza implements Moments.LoadMomentsResult {
        private final Status zzOt;
        private final String zzaHn;
        private final String zzaHo;
        private final MomentBuffer zzaHp;

        public zza(Status status, DataHolder dataHolder, String str, String str2) {
            this.zzOt = status;
            this.zzaHn = str;
            this.zzaHo = str2;
            this.zzaHp = dataHolder != null ? new MomentBuffer(dataHolder) : null;
        }

        @Override // com.google.android.gms.plus.Moments.LoadMomentsResult
        public MomentBuffer getMomentBuffer() {
            return this.zzaHp;
        }

        @Override // com.google.android.gms.plus.Moments.LoadMomentsResult
        public String getNextPageToken() {
            return this.zzaHn;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.plus.Moments.LoadMomentsResult
        public String getUpdated() {
            return this.zzaHo;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzaHp != null) {
                this.zzaHp.release();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzb implements People.LoadPeopleResult {
        private final Status zzOt;
        private final String zzaHn;
        private final PersonBuffer zzaHq;

        public zzb(Status status, DataHolder dataHolder, String str) {
            this.zzOt = status;
            this.zzaHn = str;
            this.zzaHq = dataHolder != null ? new PersonBuffer(dataHolder) : null;
        }

        @Override // com.google.android.gms.plus.People.LoadPeopleResult
        public String getNextPageToken() {
            return this.zzaHn;
        }

        @Override // com.google.android.gms.plus.People.LoadPeopleResult
        public PersonBuffer getPersonBuffer() {
            return this.zzaHq;
        }

        @Override // com.google.android.gms.common.api.Result
        public Status getStatus() {
            return this.zzOt;
        }

        @Override // com.google.android.gms.common.api.Releasable
        public void release() {
            if (this.zzaHq != null) {
                this.zzaHq.release();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzc extends com.google.android.gms.plus.internal.zza {
        private final zza.zzb<Status> zzayZ;

        public zzc(zza.zzb<Status> zzbVar) {
            this.zzayZ = zzbVar;
        }

        @Override // com.google.android.gms.plus.internal.zza, com.google.android.gms.plus.internal.zzb
        public void zzaO(Status status) {
            this.zzayZ.zzm(status);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzd extends com.google.android.gms.plus.internal.zza {
        private final zza.zzb<Moments.LoadMomentsResult> zzayZ;

        public zzd(zza.zzb<Moments.LoadMomentsResult> zzbVar) {
            this.zzayZ = zzbVar;
        }

        @Override // com.google.android.gms.plus.internal.zza, com.google.android.gms.plus.internal.zzb
        public void zza(DataHolder dataHolder, String str, String str2) {
            Status status = new Status(dataHolder.getStatusCode(), null, dataHolder.zznb() != null ? (PendingIntent) dataHolder.zznb().getParcelable("pendingIntent") : null);
            if (!status.isSuccess() && dataHolder != null) {
                if (!dataHolder.isClosed()) {
                    dataHolder.close();
                }
                dataHolder = null;
            }
            this.zzayZ.zzm(new zza(status, dataHolder, str, str2));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* renamed from: com.google.android.gms.plus.internal.zze$zze  reason: collision with other inner class name */
    /* loaded from: classes.dex */
    public static final class BinderC0233zze extends com.google.android.gms.plus.internal.zza {
        private final zza.zzb<People.LoadPeopleResult> zzayZ;

        public BinderC0233zze(zza.zzb<People.LoadPeopleResult> zzbVar) {
            this.zzayZ = zzbVar;
        }

        @Override // com.google.android.gms.plus.internal.zza, com.google.android.gms.plus.internal.zzb
        public void zza(DataHolder dataHolder, String str) {
            Status status = new Status(dataHolder.getStatusCode(), null, dataHolder.zznb() != null ? (PendingIntent) dataHolder.zznb().getParcelable("pendingIntent") : null);
            if (!status.isSuccess() && dataHolder != null) {
                if (!dataHolder.isClosed()) {
                    dataHolder.close();
                }
                dataHolder = null;
            }
            this.zzayZ.zzm(new zzb(status, dataHolder, str));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static final class zzf extends com.google.android.gms.plus.internal.zza {
        private final zza.zzb<Status> zzayZ;

        public zzf(zza.zzb<Status> zzbVar) {
            this.zzayZ = zzbVar;
        }

        @Override // com.google.android.gms.plus.internal.zza, com.google.android.gms.plus.internal.zzb
        public void zzi(int i, Bundle bundle) {
            this.zzayZ.zzm(new Status(i, null, bundle != null ? (PendingIntent) bundle.getParcelable("pendingIntent") : null));
        }
    }

    public zze(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, PlusSession plusSession, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 2, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzaHm = plusSession;
    }

    public static boolean zze(Set<Scope> set) {
        if (set == null || set.isEmpty()) {
            return false;
        }
        return (set.size() == 1 && set.contains(new Scope("plus_one_placeholder_scope"))) ? false : true;
    }

    private Bundle zzkS() {
        Bundle zzxE = this.zzaHm.zzxE();
        zzxE.putStringArray("request_visible_actions", this.zzaHm.zzxy());
        zzxE.putString("auth_package", this.zzaHm.zzxA());
        return zzxE;
    }

    public String getAccountName() {
        zznL();
        try {
            return zznM().getAccountName();
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.plus.internal.IPlusService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.plus.service.START";
    }

    @Override // com.google.android.gms.common.internal.zzi, com.google.android.gms.common.api.Api.Client
    public boolean requiresSignIn() {
        return zze(zznK().zzb(Plus.API));
    }

    public ICancelToken zza(zza.zzb<People.LoadPeopleResult> zzbVar, int i, String str) {
        zznL();
        BinderC0233zze binderC0233zze = new BinderC0233zze(zzbVar);
        try {
            return zznM().zza(binderC0233zze, 1, i, -1, str);
        } catch (RemoteException e) {
            binderC0233zze.zza(DataHolder.zzbi(8), (String) null);
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    public void zza(int i, IBinder iBinder, Bundle bundle, int i2) {
        if (i == 0 && bundle != null && bundle.containsKey("loaded_person")) {
            this.zzaHl = PersonEntity.zzp(bundle.getByteArray("loaded_person"));
        }
        super.zza(i, iBinder, bundle, i2);
    }

    public void zza(zza.zzb<Moments.LoadMomentsResult> zzbVar, int i, String str, Uri uri, String str2, String str3) {
        zznL();
        zzd zzdVar = zzbVar != null ? new zzd(zzbVar) : null;
        try {
            zznM().zza(zzdVar, i, str, uri, str2, str3);
        } catch (RemoteException e) {
            zzdVar.zza(DataHolder.zzbi(8), (String) null, (String) null);
        }
    }

    public void zza(zza.zzb<Status> zzbVar, Moment moment) {
        zznL();
        zzc zzcVar = zzbVar != null ? new zzc(zzbVar) : null;
        try {
            zznM().zza(zzcVar, SafeParcelResponse.zza((MomentEntity) moment));
        } catch (RemoteException e) {
            if (zzcVar == null) {
                throw new IllegalStateException(e);
            }
            zzcVar.zzaO(new Status(8, null, null));
        }
    }

    public void zza(zza.zzb<People.LoadPeopleResult> zzbVar, Collection<String> collection) {
        zznL();
        BinderC0233zze binderC0233zze = new BinderC0233zze(zzbVar);
        try {
            zznM().zza(binderC0233zze, new ArrayList(collection));
        } catch (RemoteException e) {
            binderC0233zze.zza(DataHolder.zzbi(8), (String) null);
        }
    }

    public void zzd(zza.zzb<People.LoadPeopleResult> zzbVar, String[] strArr) {
        zza(zzbVar, Arrays.asList(strArr));
    }

    public void zzdX(String str) {
        zznL();
        try {
            zznM().zzdX(str);
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzdu */
    public com.google.android.gms.plus.internal.zzd zzT(IBinder iBinder) {
        return zzd.zza.zzdt(iBinder);
    }

    public void zzi(zza.zzb<Moments.LoadMomentsResult> zzbVar) {
        zza(zzbVar, 20, null, null, null, "me");
    }

    public void zzj(zza.zzb<People.LoadPeopleResult> zzbVar) {
        zznL();
        BinderC0233zze binderC0233zze = new BinderC0233zze(zzbVar);
        try {
            zznM().zza(binderC0233zze, 2, 1, -1, null);
        } catch (RemoteException e) {
            binderC0233zze.zza(DataHolder.zzbi(8), (String) null);
        }
    }

    public void zzk(zza.zzb<Status> zzbVar) {
        zznL();
        zzxr();
        zzf zzfVar = new zzf(zzbVar);
        try {
            zznM().zzb(zzfVar);
        } catch (RemoteException e) {
            zzfVar.zzi(8, null);
        }
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zzkR() {
        return zzkS();
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zznN() {
        return zzkS();
    }

    public ICancelToken zzq(zza.zzb<People.LoadPeopleResult> zzbVar, String str) {
        return zza(zzbVar, 0, str);
    }

    public void zzxr() {
        zznL();
        try {
            this.zzaHl = null;
            zznM().zzxr();
        } catch (RemoteException e) {
            throw new IllegalStateException(e);
        }
    }

    public Person zzxu() {
        zznL();
        return this.zzaHl;
    }
}
