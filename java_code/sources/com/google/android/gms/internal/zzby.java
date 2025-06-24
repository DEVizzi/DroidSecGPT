package com.google.android.gms.internal;

import android.content.Context;
import android.content.SharedPreferences;
import com.google.android.gms.common.GooglePlayServicesUtil;
@zzgd
/* loaded from: classes.dex */
public class zzby {
    private final Object zzqt = new Object();
    private boolean zzpb = false;
    private SharedPreferences zztB = null;

    public <T> T zzc(zzbv<T> zzbvVar) {
        synchronized (this.zzqt) {
            if (this.zzpb) {
                return zzbvVar.zza(this.zztB);
            }
            return zzbvVar.zzcY();
        }
    }

    public void zzw(Context context) {
        synchronized (this.zzqt) {
            if (this.zzpb) {
                return;
            }
            Context remoteContext = GooglePlayServicesUtil.getRemoteContext(context);
            if (remoteContext == null) {
                return;
            }
            this.zztB = com.google.android.gms.ads.internal.zzo.zzbC().zzv(remoteContext);
            this.zzpb = true;
        }
    }
}
