package com.google.android.gms.plus;

import android.content.Context;
import android.os.Looper;
import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.internal.zzu;
import com.google.android.gms.internal.zzln;
import com.google.android.gms.internal.zzpa;
import com.google.android.gms.internal.zzpb;
import com.google.android.gms.internal.zzpc;
import com.google.android.gms.internal.zzpd;
import com.google.android.gms.internal.zzpe;
import com.google.android.gms.plus.internal.PlusCommonExtras;
import com.google.android.gms.plus.internal.PlusSession;
import com.google.android.gms.plus.internal.zze;
import java.util.HashSet;
import java.util.Set;
/* loaded from: classes.dex */
public final class Plus {
    public static final Api.ClientKey<zze> zzNX = new Api.ClientKey<>();
    static final Api.zza<zze, PlusOptions> zzNY = new Api.zza<zze, PlusOptions>() { // from class: com.google.android.gms.plus.Plus.1
        @Override // com.google.android.gms.common.api.Api.zza
        public int getPriority() {
            return 2;
        }

        @Override // com.google.android.gms.common.api.Api.zza
        public zze zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, PlusOptions plusOptions, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener) {
            if (plusOptions == null) {
                plusOptions = new PlusOptions();
            }
            return new zze(context, looper, zzeVar, new PlusSession(zzeVar.zzns(), zzln.zzc(zzeVar.zznw()), (String[]) plusOptions.zzaHc.toArray(new String[0]), new String[0], context.getPackageName(), context.getPackageName(), null, new PlusCommonExtras()), connectionCallbacks, onConnectionFailedListener);
        }
    };
    public static final Api<PlusOptions> API = new Api<>("Plus.API", zzNY, zzNX, new Scope[0]);
    public static final Scope SCOPE_PLUS_LOGIN = new Scope(Scopes.PLUS_LOGIN);
    public static final Scope SCOPE_PLUS_PROFILE = new Scope(Scopes.PLUS_ME);
    public static final Moments MomentsApi = new zzpd();
    public static final People PeopleApi = new zzpe();
    public static final Account AccountApi = new zzpa();
    public static final zzb zzaGZ = new zzpc();
    public static final com.google.android.gms.plus.zza zzaHa = new zzpb();

    /* loaded from: classes.dex */
    public static final class PlusOptions implements Api.ApiOptions.Optional {
        final String zzaHb;
        final Set<String> zzaHc;

        /* loaded from: classes.dex */
        public static final class Builder {
            String zzaHb;
            final Set<String> zzaHc = new HashSet();

            public Builder addActivityTypes(String... activityTypes) {
                zzu.zzb(activityTypes, "activityTypes may not be null.");
                for (String str : activityTypes) {
                    this.zzaHc.add(str);
                }
                return this;
            }

            public PlusOptions build() {
                return new PlusOptions(this);
            }

            public Builder setServerClientId(String clientId) {
                this.zzaHb = clientId;
                return this;
            }
        }

        private PlusOptions() {
            this.zzaHb = null;
            this.zzaHc = new HashSet();
        }

        private PlusOptions(Builder builder) {
            this.zzaHb = builder.zzaHb;
            this.zzaHc = builder.zzaHc;
        }

        public static Builder builder() {
            return new Builder();
        }
    }

    /* loaded from: classes.dex */
    public static abstract class zza<R extends Result> extends zza.AbstractC0032zza<R, zze> {
        public zza(GoogleApiClient googleApiClient) {
            super(Plus.zzNX, googleApiClient);
        }
    }

    private Plus() {
    }

    public static zze zzf(GoogleApiClient googleApiClient, boolean z) {
        zzu.zzb(googleApiClient != null, "GoogleApiClient parameter is required.");
        zzu.zza(googleApiClient.isConnected(), "GoogleApiClient must be connected.");
        zzu.zza(googleApiClient.zza(API), "GoogleApiClient is not configured to use the Plus.API Api. Pass this into GoogleApiClient.Builder#addApi() to use this feature.");
        boolean hasConnectedApi = googleApiClient.hasConnectedApi(API);
        if (!z || hasConnectedApi) {
            if (hasConnectedApi) {
                return (zze) googleApiClient.zza(zzNX);
            }
            return null;
        }
        throw new IllegalStateException("GoogleApiClient has an optional Plus.API and is not connected to Plus. Use GoogleApiClient.hasConnectedApi(Plus.API) to guard this call.");
    }
}
