package com.google.android.gms.search;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.zze;
import com.google.android.gms.internal.zzpo;
import com.google.android.gms.internal.zzpp;
/* loaded from: classes.dex */
public class SearchAuth {
    private static final Api.zza<zzpo, Api.ApiOptions.NoOptions> zzaJH = new Api.zza<zzpo, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.search.SearchAuth.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzu */
        public zzpo zza(Context context, Looper looper, zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzpo(context, connectionCallbacks, onConnectionFailedListener, zzeVar);
        }
    };
    public static final Api.ClientKey<zzpo> zzNX = new Api.ClientKey<>();
    public static final Api<Api.ApiOptions.NoOptions> API = new Api<>("SearchAuth.API", zzaJH, zzNX, new Scope[0]);
    public static final SearchAuthApi SearchAuthApi = new zzpp();

    /* loaded from: classes.dex */
    public static class StatusCodes {
        public static final int AUTH_DISABLED = 10000;
        public static final int AUTH_THROTTLED = 10001;
        public static final int DEVELOPER_ERROR = 10;
        public static final int INTERNAL_ERROR = 8;
        public static final int SUCCESS = 0;
    }

    private SearchAuth() {
    }
}
