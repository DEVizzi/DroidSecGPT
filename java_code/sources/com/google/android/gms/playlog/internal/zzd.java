package com.google.android.gms.playlog.internal;

import android.os.Bundle;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.internal.zzoz;
/* loaded from: classes.dex */
public class zzd implements GoogleApiClient.ConnectionCallbacks, GoogleApiClient.OnConnectionFailedListener {
    private final zzoz.zza zzaGN;
    private zzf zzaGD = null;
    private boolean zzaGO = true;

    public zzd(zzoz.zza zzaVar) {
        this.zzaGN = zzaVar;
    }

    @Override // com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks
    public void onConnected(Bundle connectionHint) {
        this.zzaGD.zzak(false);
        if (this.zzaGO && this.zzaGN != null) {
            this.zzaGN.zzxl();
        }
        this.zzaGO = false;
    }

    @Override // com.google.android.gms.common.api.GoogleApiClient.OnConnectionFailedListener
    public void onConnectionFailed(ConnectionResult result) {
        this.zzaGD.zzak(true);
        if (this.zzaGO && this.zzaGN != null) {
            if (result.hasResolution()) {
                this.zzaGN.zzf(result.getResolution());
            } else {
                this.zzaGN.zzxm();
            }
        }
        this.zzaGO = false;
    }

    @Override // com.google.android.gms.common.api.GoogleApiClient.ConnectionCallbacks
    public void onConnectionSuspended(int cause) {
        this.zzaGD.zzak(true);
    }

    public void zza(zzf zzfVar) {
        this.zzaGD = zzfVar;
    }

    public void zzaj(boolean z) {
        this.zzaGO = z;
    }
}
