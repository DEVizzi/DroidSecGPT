package com.google.android.gms.safetynet;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.zze;
import com.google.android.gms.internal.zzpj;
import com.google.android.gms.internal.zzpk;
import com.google.android.gms.internal.zzpl;
/* loaded from: classes.dex */
public final class SafetyNet {
    public static final Api.ClientKey<zzpk> zzNX = new Api.ClientKey<>();
    public static final Api.zza<zzpk, Api.ApiOptions.NoOptions> zzNY = new Api.zza<zzpk, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.safetynet.SafetyNet.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzt */
        public zzpk zza(Context context, Looper looper, zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzpk(context, looper, connectionCallbacks, onConnectionFailedListener);
        }
    };
    public static final Api<Api.ApiOptions.NoOptions> API = new Api<>("SafetyNet.API", zzNY, zzNX, new Scope[0]);
    public static final SafetyNetApi SafetyNetApi = new zzpj();
    public static final zzb zzaJy = new zzpl();

    private SafetyNet() {
    }
}
