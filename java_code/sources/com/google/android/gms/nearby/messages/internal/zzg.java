package com.google.android.gms.nearby.messages.internal;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
/* loaded from: classes.dex */
public class zzg implements com.google.android.gms.nearby.messages.zzc {
    public static final Api.ClientKey<zzf> zzNX = new Api.ClientKey<>();
    public static final Api.zza<zzf, com.google.android.gms.nearby.messages.zze> zzNY = new Api.zza<zzf, com.google.android.gms.nearby.messages.zze>() { // from class: com.google.android.gms.nearby.messages.internal.zzg.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public zzf zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, com.google.android.gms.nearby.messages.zze zzeVar2, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzf(context, looper, connectionCallbacks, onConnectionFailedListener, zzeVar, zzeVar2);
        }
    };
}
