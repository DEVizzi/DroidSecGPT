package com.google.android.gms.fitness;

import android.content.Intent;
import android.os.Build;
import com.google.android.gms.common.Scopes;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.internal.zzlx;
import com.google.android.gms.internal.zzly;
import com.google.android.gms.internal.zzlz;
import com.google.android.gms.internal.zzma;
import com.google.android.gms.internal.zzmb;
import com.google.android.gms.internal.zzmc;
import com.google.android.gms.internal.zzmd;
import com.google.android.gms.internal.zzmx;
import com.google.android.gms.internal.zzmz;
import com.google.android.gms.internal.zzna;
import com.google.android.gms.internal.zznb;
import com.google.android.gms.internal.zznc;
import com.google.android.gms.internal.zznd;
import com.google.android.gms.internal.zzne;
import com.google.android.gms.internal.zznf;
import com.google.android.gms.internal.zznh;
import java.util.concurrent.TimeUnit;
/* loaded from: classes.dex */
public class Fitness {
    public static final String ACTION_TRACK = "vnd.google.fitness.TRACK";
    public static final String ACTION_VIEW = "vnd.google.fitness.VIEW";
    public static final String ACTION_VIEW_GOAL = "vnd.google.fitness.VIEW_GOAL";
    public static final String EXTRA_END_TIME = "vnd.google.fitness.end_time";
    public static final String EXTRA_START_TIME = "vnd.google.fitness.start_time";
    public static final Api.ClientKey<zzlx> zzajw = new Api.ClientKey<>();
    public static final Api.ClientKey<zzly> zzajx = new Api.ClientKey<>();
    public static final Api.ClientKey<zzlz> zzajy = new Api.ClientKey<>();
    public static final Api.ClientKey<zzma> zzajz = new Api.ClientKey<>();
    public static final Api.ClientKey<zzmb> zzajA = new Api.ClientKey<>();
    public static final Api.ClientKey<zzmc> zzajB = new Api.ClientKey<>();
    public static final Api.ClientKey<zzmd> zzajC = new Api.ClientKey<>();
    @Deprecated
    public static final Void API = null;
    public static final Api<Api.ApiOptions.NoOptions> SENSORS_API = new Api<>("Fitness.SENSORS_API", new zzmc.zzb(), zzajB, new Scope[0]);
    public static final SensorsApi SensorsApi = new zzne();
    public static final Api<Api.ApiOptions.NoOptions> RECORDING_API = new Api<>("Fitness.RECORDING_API", new zzmb.zzb(), zzajA, new Scope[0]);
    public static final RecordingApi RecordingApi = new zznd();
    public static final Api<Api.ApiOptions.NoOptions> SESSIONS_API = new Api<>("Fitness.SESSIONS_API", new zzmd.zzb(), zzajC, new Scope[0]);
    public static final SessionsApi SessionsApi = new zznf();
    public static final Api<Api.ApiOptions.NoOptions> HISTORY_API = new Api<>("Fitness.HISTORY_API", new zzlz.zzb(), zzajy, new Scope[0]);
    public static final HistoryApi HistoryApi = new zznb();
    public static final Api<Api.ApiOptions.NoOptions> CONFIG_API = new Api<>("Fitness.CONFIG_API", new zzly.zzb(), zzajx, new Scope[0]);
    public static final ConfigApi ConfigApi = new zzna();
    public static final Api<Api.ApiOptions.NoOptions> BLE_API = new Api<>("Fitness.BLE_API", new zzlx.zzb(), zzajw, new Scope[0]);
    public static final BleApi BleApi = zzqo();
    public static final Api<Api.ApiOptions.NoOptions> zzada = new Api<>("Fitness.INTERNAL_API", new zzma.zza(), zzajz, new Scope[0]);
    public static final zzmx zzajD = new zznc();
    public static final Scope SCOPE_ACTIVITY_READ = new Scope(Scopes.FITNESS_ACTIVITY_READ);
    public static final Scope SCOPE_ACTIVITY_READ_WRITE = new Scope(Scopes.FITNESS_ACTIVITY_READ_WRITE);
    public static final Scope SCOPE_LOCATION_READ = new Scope(Scopes.FITNESS_LOCATION_READ);
    public static final Scope SCOPE_LOCATION_READ_WRITE = new Scope(Scopes.FITNESS_LOCATION_READ_WRITE);
    public static final Scope SCOPE_BODY_READ = new Scope(Scopes.FITNESS_BODY_READ);
    public static final Scope SCOPE_BODY_READ_WRITE = new Scope(Scopes.FITNESS_BODY_READ_WRITE);
    public static final Scope SCOPE_NUTRITION_READ = new Scope(Scopes.FITNESS_NUTRITION_READ);
    public static final Scope SCOPE_NUTRITION_READ_WRITE = new Scope(Scopes.FITNESS_NUTRITION_READ_WRITE);

    private Fitness() {
    }

    public static long getEndTime(Intent intent, TimeUnit timeUnit) {
        long longExtra = intent.getLongExtra(EXTRA_END_TIME, -1L);
        if (longExtra == -1) {
            return -1L;
        }
        return timeUnit.convert(longExtra, TimeUnit.MILLISECONDS);
    }

    public static long getStartTime(Intent intent, TimeUnit timeUnit) {
        long longExtra = intent.getLongExtra(EXTRA_START_TIME, -1L);
        if (longExtra == -1) {
            return -1L;
        }
        return timeUnit.convert(longExtra, TimeUnit.MILLISECONDS);
    }

    private static BleApi zzqo() {
        return Build.VERSION.SDK_INT >= 18 ? new zzmz() : new zznh();
    }
}
