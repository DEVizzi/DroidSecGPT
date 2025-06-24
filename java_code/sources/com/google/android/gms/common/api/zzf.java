package com.google.android.gms.common.api;

import android.os.Bundle;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.Api;
import com.google.android.gms.common.api.zza;
import com.google.android.gms.common.api.zzg;
/* loaded from: classes.dex */
public class zzf implements zzh {
    private final zzg zzWK;

    public zzf(zzg zzgVar) {
        this.zzWK = zzgVar;
    }

    @Override // com.google.android.gms.common.api.zzh
    public void begin() {
        this.zzWK.zzmL();
    }

    @Override // com.google.android.gms.common.api.zzh
    public void connect() {
        this.zzWK.zzmM();
    }

    @Override // com.google.android.gms.common.api.zzh
    public String getName() {
        return "DISCONNECTED";
    }

    @Override // com.google.android.gms.common.api.zzh
    public void onConnected(Bundle connectionHint) {
    }

    @Override // com.google.android.gms.common.api.zzh
    public void onConnectionSuspended(int cause) {
    }

    @Override // com.google.android.gms.common.api.zzh
    public <A extends Api.Client, R extends Result, T extends zza.AbstractC0032zza<R, A>> T zza(T t) {
        this.zzWK.zzXo.add(t);
        return t;
    }

    @Override // com.google.android.gms.common.api.zzh
    public void zza(ConnectionResult connectionResult, Api<?> api, int i) {
    }

    @Override // com.google.android.gms.common.api.zzh
    public void zzaV(int i) {
        if (i == -1) {
            for (zzg.zze<?> zzeVar : this.zzWK.zzXo) {
                zzeVar.cancel();
            }
            this.zzWK.zzXo.clear();
            this.zzWK.zzmK();
            this.zzWK.zzXv.clear();
        }
    }

    @Override // com.google.android.gms.common.api.zzh
    public <A extends Api.Client, T extends zza.AbstractC0032zza<? extends Result, A>> T zzb(T t) {
        throw new IllegalStateException("GoogleApiClient is not connected yet.");
    }
}
