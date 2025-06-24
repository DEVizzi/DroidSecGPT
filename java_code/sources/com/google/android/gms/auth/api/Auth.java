package com.google.android.gms.auth.api;

import android.content.Context;
import android.os.Bundle;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.auth.api.credentials.CredentialsApi;
import com.google.android.gms.auth.api.credentials.internal.CredentialsClientImpl;
import com.google.android.gms.auth.api.credentials.internal.zzc;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.zze;
import com.google.android.gms.internal.zzje;
import com.google.android.gms.internal.zzjf;
import com.google.android.gms.internal.zzjg;
import com.google.android.gms.internal.zzjj;
import com.google.android.gms.internal.zzjm;
import com.google.android.gms.internal.zzjn;
import com.google.android.gms.internal.zzjp;
import com.google.android.gms.internal.zzjq;
/* loaded from: classes.dex */
public final class Auth {
    public static final Api.ClientKey<zzjj> zzOE = new Api.ClientKey<>();
    public static final Api.ClientKey<CredentialsClientImpl> CLIENT_KEY_CREDENTIALS_API = new Api.ClientKey<>();
    public static final Api.ClientKey<zzjg> zzOF = new Api.ClientKey<>();
    public static final Api.ClientKey<zzjq> zzOG = new Api.ClientKey<>();
    private static final Api.zza<zzjj, zza> zzOH = new Api.zza<zzjj, zza>() { // from class: com.google.android.gms.auth.api.Auth.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public zzjj zza(Context context, Looper looper, zze zzeVar, zza zzaVar, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzjj(context, looper, zzeVar, zzaVar, connectionCallbacks, onConnectionFailedListener);
        }
    };
    private static final Api.zza<CredentialsClientImpl, Api.ApiOptions.NoOptions> zzOI = new Api.zza<CredentialsClientImpl, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.auth.api.Auth.2
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzd */
        public CredentialsClientImpl zza(Context context, Looper looper, zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new CredentialsClientImpl(context, looper, connectionCallbacks, onConnectionFailedListener);
        }
    };
    private static final Api.zza<zzjg, Api.ApiOptions.NoOptions> zzOJ = new Api.zza<zzjg, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.auth.api.Auth.3
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zze */
        public zzjg zza(Context context, Looper looper, zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzjg(context, looper, zzeVar, connectionCallbacks, onConnectionFailedListener);
        }
    };
    private static final Api.zza<zzjq, Api.ApiOptions.NoOptions> zzOK = new Api.zza<zzjq, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.auth.api.Auth.4
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzf */
        public zzjq zza(Context context, Looper looper, zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzjq(context, looper, connectionCallbacks, onConnectionFailedListener);
        }
    };
    public static final Api<zza> zzOL = new Api<>("Auth.PROXY_API", zzOH, zzOE, new Scope[0]);
    public static final Api<Api.ApiOptions.NoOptions> CREDENTIALS_API = new Api<>("Auth.CREDENTIALS_API", zzOI, CLIENT_KEY_CREDENTIALS_API, new Scope[0]);
    public static final Api<Api.ApiOptions.NoOptions> zzOM = new Api<>("Auth.SIGN_IN_API", zzOK, zzOG, new Scope[0]);
    public static final Api<Api.ApiOptions.NoOptions> zzON = new Api<>("Auth.ACCOUNT_STATUS_API", zzOJ, zzOF, new Scope[0]);
    public static final com.google.android.gms.auth.api.proxy.zza zzOO = new zzjm();
    public static final CredentialsApi CredentialsApi = new zzc();
    public static final zzje zzOP = new zzjf();
    public static final zzjn zzOQ = new zzjp();

    /* loaded from: classes.dex */
    public static final class zza implements Api.ApiOptions.Optional {
        private final Bundle zzOR;

        public Bundle zzkY() {
            return new Bundle(this.zzOR);
        }
    }

    private Auth() {
    }
}
