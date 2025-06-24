package com.google.android.gms.common.api;

import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import com.google.android.gms.common.api.Api.ApiOptions;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.common.internal.IAccountAccessor;
import com.google.android.gms.common.internal.zzu;
import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
/* loaded from: classes.dex */
public final class Api<O extends ApiOptions> {
    private final String mName;
    private final ClientKey<?> zzVu;
    private final zza<?, O> zzWi;
    private final zzc<?, O> zzWj;
    private final zzd<?> zzWk;
    private final ArrayList<Scope> zzWl;

    /* loaded from: classes.dex */
    public interface ApiOptions {

        /* loaded from: classes.dex */
        public interface HasOptions extends ApiOptions {
        }

        /* loaded from: classes.dex */
        public static final class NoOptions implements NotRequiredOptions {
            private NoOptions() {
            }
        }

        /* loaded from: classes.dex */
        public interface NotRequiredOptions extends ApiOptions {
        }

        /* loaded from: classes.dex */
        public interface Optional extends HasOptions, NotRequiredOptions {
        }
    }

    /* loaded from: classes.dex */
    public interface Client {
        void connect(GoogleApiClient.ConnectionProgressReportCallbacks connectionProgressReportCallbacks);

        void disconnect();

        void dump(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr);

        void getRemoteService(IAccountAccessor iAccountAccessor, Set<Scope> set);

        boolean isConnected();

        boolean isConnecting();

        boolean requiresAccount();

        boolean requiresSignIn();

        void validateAccount(IAccountAccessor iAccountAccessor);
    }

    /* loaded from: classes.dex */
    public static final class ClientKey<C extends Client> {
    }

    /* loaded from: classes.dex */
    public interface zza<T extends Client, O> {
        int getPriority();

        T zza(Context context, Looper looper, com.google.android.gms.common.internal.zze zzeVar, O o, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener);
    }

    /* loaded from: classes.dex */
    public interface zzb<T extends IInterface> {
        String getServiceDescriptor();

        String getStartServiceAction();

        T zzT(IBinder iBinder);
    }

    /* loaded from: classes.dex */
    public interface zzc<T extends zzb, O> {
        T zzl(O o);

        int zzmu();
    }

    /* loaded from: classes.dex */
    public static final class zzd<C extends zzb> {
    }

    /* JADX WARN: Multi-variable type inference failed */
    public <C extends Client> Api(String name, zza<C, O> clientBuilder, ClientKey<C> clientKey, Scope... impliedScopes) {
        zzu.zzb(clientBuilder, "Cannot construct an Api with a null ClientBuilder");
        zzu.zzb(clientKey, "Cannot construct an Api with a null ClientKey");
        this.mName = name;
        this.zzWi = clientBuilder;
        this.zzWj = null;
        this.zzVu = clientKey;
        this.zzWk = null;
        this.zzWl = new ArrayList<>(Arrays.asList(impliedScopes));
    }

    public String getName() {
        return this.mName;
    }

    public zza<?, O> zzmp() {
        zzu.zza(this.zzWi != null, "This API was constructed with a SimpleClientBuilder. Use getSimpleClientBuilder");
        return this.zzWi;
    }

    public zzc<?, O> zzmq() {
        zzu.zza(this.zzWj != null, "This API was constructed with a ClientBuilder. Use getClientBuilder");
        return this.zzWj;
    }

    public List<Scope> zzmr() {
        return this.zzWl;
    }

    public ClientKey<?> zzms() {
        zzu.zza(this.zzVu != null, "This API was constructed with a SimpleClientKey. Use getSimpleClientKey");
        return this.zzVu;
    }

    public boolean zzmt() {
        return this.zzWk != null;
    }
}
