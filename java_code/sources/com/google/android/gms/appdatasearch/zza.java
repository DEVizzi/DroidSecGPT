package com.google.android.gms.appdatasearch;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.internal.zzit;
import com.google.android.gms.internal.zziv;
/* loaded from: classes.dex */
public final class zza {
    public static final Api.ClientKey<zzit> zzMO = new Api.ClientKey<>();
    private static final Api.zza<zzit, Api.ApiOptions.NoOptions> zzMP = new Api.zza<zzit, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.appdatasearch.zza.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public zzit zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzit(context, looper, connectionCallbacks, onConnectionFailedListener);
        }
    };
    public static final Api<Api.ApiOptions.NoOptions> zzMQ = new Api<>("AppDataSearch.LIGHTWEIGHT_API", zzMP, zzMO, new Scope[0]);
    public static final zzk zzMR = new zziv();
}
