package com.google.android.gms.cast;

import android.content.Context;
import android.os.Looper;
import android.support.v7.internal.widget.ActivityChooserView;
import android.view.Display;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.internal.zze;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzka;
import com.google.android.gms.internal.zzkb;
/* loaded from: classes.dex */
public final class CastRemoteDisplay {
    private static final Api.ClientKey<zzkb> zzNX = new Api.ClientKey<>();
    private static final Api.zza<zzkb, CastRemoteDisplayOptions> zzNY = new Api.zza<zzkb, CastRemoteDisplayOptions>() { // from class: com.google.android.gms.cast.CastRemoteDisplay.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public zzkb zza(Context context, Looper looper, zze zzeVar, CastRemoteDisplayOptions castRemoteDisplayOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            return new zzkb(context, looper, castRemoteDisplayOptions.zzQE, castRemoteDisplayOptions.zzQU, connectionCallbacks, onConnectionFailedListener);
        }
    };
    public static final Api<CastRemoteDisplayOptions> API = new Api<>("CastRemoteDisplay.API", zzNY, zzNX, new Scope[0]);
    public static final CastRemoteDisplayApi CastRemoteDisplayApi = new zzka(zzNX);

    /* loaded from: classes.dex */
    public static final class CastRemoteDisplayOptions implements Api.ApiOptions.HasOptions {
        final CastDevice zzQE;
        final CastRemoteDisplaySessionCallbacks zzQU;

        /* loaded from: classes.dex */
        public static final class Builder {
            CastDevice zzQH;
            CastRemoteDisplaySessionCallbacks zzQV;

            public Builder(CastDevice castDevice, CastRemoteDisplaySessionCallbacks callbacks) {
                zzu.zzb(castDevice, "CastDevice parameter cannot be null");
                this.zzQH = castDevice;
                this.zzQV = callbacks;
            }

            public CastRemoteDisplayOptions build() {
                return new CastRemoteDisplayOptions(this);
            }
        }

        private CastRemoteDisplayOptions(Builder builder) {
            this.zzQE = builder.zzQH;
            this.zzQU = builder.zzQV;
        }
    }

    /* loaded from: classes.dex */
    public interface CastRemoteDisplaySessionCallbacks {
        void onRemoteDisplayEnded(Status status);
    }

    /* loaded from: classes.dex */
    public interface CastRemoteDisplaySessionResult extends Result {
        Display getPresentationDisplay();
    }

    private CastRemoteDisplay() {
    }
}
