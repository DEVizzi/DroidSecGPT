package com.google.android.gms.internal;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
/* loaded from: classes.dex */
public class zzoi implements com.google.android.gms.nearby.bootstrap.zza {
    public static final Api.ClientKey<zzoh> zzNX = new Api.ClientKey<>();
    public static final Api.zza<zzoh, Api.ApiOptions.NoOptions> zzNY = new Api.zza<zzoh, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.internal.zzoi.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzp */
        public zzoh zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzoh(context, looper, connectionCallbacks, onConnectionFailedListener, zzeVar);
        }
    };
}
