package com.google.android.gms.internal;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import java.util.concurrent.Executors;
/* loaded from: classes.dex */
public final class zzpq {
    public static final Api.ClientKey<com.google.android.gms.signin.internal.zzh> zzNX = new Api.ClientKey<>();
    public static final Api.ClientKey<com.google.android.gms.signin.internal.zzh> zzajz = new Api.ClientKey<>();
    public static final Api.zza<com.google.android.gms.signin.internal.zzh, zzpt> zzNY = new Api.zza<com.google.android.gms.signin.internal.zzh, zzpt>() { // from class: com.google.android.gms.internal.zzpq.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public com.google.android.gms.signin.internal.zzh zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, zzpt zzptVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new com.google.android.gms.signin.internal.zzh(context, looper, true, zzeVar, zzptVar == null ? zzpt.zzaJQ : zzptVar, connectionCallbacks, onConnectionFailedListener, Executors.newSingleThreadExecutor());
        }
    };
    static final Api.zza<com.google.android.gms.signin.internal.zzh, Api.ApiOptions.NoOptions> zzaJO = new Api.zza<com.google.android.gms.signin.internal.zzh, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.internal.zzpq.2
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzv */
        public com.google.android.gms.signin.internal.zzh zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new com.google.android.gms.signin.internal.zzh(context, looper, false, zzeVar, zzpt.zzaJQ, connectionCallbacks, onConnectionFailedListener, Executors.newSingleThreadExecutor());
        }
    };
    public static final Api<zzpt> API = new Api<>("SignIn.API", zzNY, zzNX, new Scope[0]);
    public static final Api<Api.ApiOptions.NoOptions> zzada = new Api<>("SignIn.INTERNAL_API", zzaJO, zzajz, new Scope[0]);
    public static final zzpr zzaJP = new com.google.android.gms.signin.internal.zzg();
}
