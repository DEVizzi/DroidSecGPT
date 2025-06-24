package com.google.android.gms.location.internal;

import android.content.Context;
import android.os.Bundle;
import android.os.DeadObjectException;
import android.os.IBinder;
import android.os.Looper;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.location.internal.zzg;
/* loaded from: classes.dex */
public class zzb extends com.google.android.gms.common.internal.zzi<zzg> {
    protected final zzn<zzg> zzayq;
    private final String zzayw;

    public zzb(Context context, Looper looper, GoogleApiClient.ConnectionCallbacks connectionCallbacks, GoogleApiClient.OnConnectionFailedListener onConnectionFailedListener, String str, com.google.android.gms.common.internal.zze zzeVar) {
        super(context, looper, 23, connectionCallbacks, onConnectionFailedListener, zzeVar);
        this.zzayq = new zzn<zzg>() { // from class: com.google.android.gms.location.internal.zzb.1
            @Override // com.google.android.gms.location.internal.zzn
            public void zznL() {
                zzb.this.zznL();
            }

            @Override // com.google.android.gms.location.internal.zzn
            /* renamed from: zzut */
            public zzg zznM() throws DeadObjectException {
                return zzb.this.zznM();
            }
        };
        this.zzayw = str;
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getServiceDescriptor() {
        return "com.google.android.gms.location.internal.IGoogleLocationManagerService";
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected String getStartServiceAction() {
        return "com.google.android.location.internal.GoogleLocationManagerService.START";
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.internal.zzi
    /* renamed from: zzbU */
    public zzg zzT(IBinder iBinder) {
        return zzg.zza.zzbW(iBinder);
    }

    @Override // com.google.android.gms.common.internal.zzi
    protected Bundle zzkR() {
        Bundle bundle = new Bundle();
        bundle.putString("client_name", this.zzayw);
        return bundle;
    }
}
