package com.google.android.gms.common.api;

import android.os.Bundle;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.zza;
/* loaded from: classes.dex */
public interface zzh {
    void begin();

    void connect();

    String getName();

    void onConnected(Bundle bundle);

    void onConnectionSuspended(int i);

    <A extends Api.Client, R extends Result, T extends zza.AbstractC0032zza<R, A>> T zza(T t);

    void zza(ConnectionResult connectionResult, Api<?> api, int i);

    void zzaV(int i);

    <A extends Api.Client, T extends zza.AbstractC0032zza<? extends Result, A>> T zzb(T t);
}
