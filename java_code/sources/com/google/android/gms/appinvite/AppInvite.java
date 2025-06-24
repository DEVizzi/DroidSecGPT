package com.google.android.gms.appinvite;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.internal.zze;
import com.google.android.gms.internal.zziw;
import com.google.android.gms.internal.zzix;
/* loaded from: classes.dex */
public final class AppInvite {
    public static final Api.ClientKey<zzix> zzNX = new Api.ClientKey<>();
    private static final Api.zza<zzix, Api.ApiOptions.NoOptions> zzNY = new Api.zza<zzix, Api.ApiOptions.NoOptions>() { // from class: com.google.android.gms.appinvite.AppInvite.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        /* renamed from: zzb */
        public zzix zza(Context context, Looper looper, zze zzeVar, Api.ApiOptions.NoOptions noOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzix(context, looper, connectionCallbacks, onConnectionFailedListener, zzeVar);
        }
    };
    public static final Api<Api.ApiOptions.NoOptions> API = new Api<>("AppInvite.API", zzNY, zzNX, new Scope[0]);
    public static final AppInviteApi AppInviteApi = new zziw();

    private AppInvite() {
    }
}
