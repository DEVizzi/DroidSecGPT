package com.google.android.gms.internal;

import android.content.Context;
import android.os.IBinder;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.fitness.Fitness;
import com.google.android.gms.internal.zzmo;
/* loaded from: classes.dex */
public class zzmd extends zzlw<zzmo> {

    /* loaded from: classes.dex */
    static abstract class zza<R extends Result> extends zza.AbstractC0032zza<R, zzmd> {
        public zza(GoogleApiClient googleApiClient) {
            super(Fitness.zzajC, googleApiClient);
        }
    }

    /* loaded from: classes.dex */
    public static class zzb implements Api.zza<zzmd, Api.ApiOptions.NoOptions> {
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzn */
        public zzmd zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzmd(context, looper, zzeVar, connectionCallbacks, onConnectionFailedListener);
        }
    }

    /* loaded from: classes.dex */
    static abstract class zzc extends zza<Status> {
        /* JADX INFO: Access modifiers changed from: package-private */
        public zzc(GoogleApiClient googleApiClient) {
            super(googleApiClient);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // com.google.android.gms.common.api.AbstractPendingResult
        /* renamed from: zzb */
        public Status createFailedResult(Status status) {
            com.google.android.gms.common.internal.zzu.zzV(!status.isSuccess());
            return status;
        }
    }

    public zzmd(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
        super(context, looper, 58, connectionCallbacks, onConnectionFailedListener, zzeVar);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.fitness.internal.IGoogleFitSessionsApi";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.gms.fitness.SessionsApi";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzbo */
    public zzmo zzT(IBinder iBinder) {
        return zzmo.zza.zzbz(iBinder);
    }
}
