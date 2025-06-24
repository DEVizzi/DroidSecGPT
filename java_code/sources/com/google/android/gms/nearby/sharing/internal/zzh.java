package com.google.android.gms.nearby.sharing.internal;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
/* loaded from: classes.dex */
public final class zzh implements com.google.android.gms.nearby.sharing.zzd {
    public static final Api.ClientKey<zze> zzNX = new Api.ClientKey<>();
    public static final Api.zza<zze, Api.ApiOptions.NoOptions> zzNY = new Api.zza<zze, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.nearby.sharing.internal.zzh.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzr */
        public zze zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zze(context, looper, connectionCallbacks, onConnectionFailedListener, zzeVar);
        }
    };
}
