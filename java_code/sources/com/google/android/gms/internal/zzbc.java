package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.zzbb;
import java.util.concurrent.Future;
@zzgd
/* loaded from: classes.dex */
public class zzbc {
    protected zzbb zza(Context context, VersionInfoParcel versionInfoParcel, final zzhs<zzbb> zzhsVar) {
        final zzbd zzbdVar = new zzbd(context, versionInfoParcel);
        zzbdVar.zza(new zzbb.zza() { // from class: com.google.android.gms.internal.zzbc.2
            @Override // com.google.android.gms.internal.zzbb.zza
            public void zzcf() {
                zzhsVar.zzf(zzbdVar);
            }
        });
        return zzbdVar;
    }

    public Future<zzbb> zza(final Context context, final VersionInfoParcel versionInfoParcel, final String str) {
        final zzhs zzhsVar = new zzhs();
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzbc.1
            @Override // java.lang.Runnable
            public void run() {
                zzbc.this.zza(context, versionInfoParcel, zzhsVar).zzs(str);
            }
        });
        return zzhsVar;
    }
}
