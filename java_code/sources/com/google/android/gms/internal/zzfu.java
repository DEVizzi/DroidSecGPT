package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.internal.zzfs;
import com.google.android.gms.internal.zzft;
import com.google.android.gms.internal.zzha;
@zzgd
/* loaded from: classes.dex */
public class zzfu extends zzfp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public zzfu(Context context, zzha.zza zzaVar, zzid zzidVar, zzft.zza zzaVar2) {
        super(context, zzaVar, zzidVar, zzaVar2);
    }

    protected void zzfn() {
    }

    @Override // com.google.android.gms.internal.zzfs
    protected void zzh(long j) throws zzfs.zza {
        zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzfu.1
            @Override // java.lang.Runnable
            public void run() {
                synchronized (zzfu.this.zzqt) {
                    if (zzfu.this.zzBt.errorCode != -2) {
                        return;
                    }
                    zzfu.this.zzoA.zzgF().zza(zzfu.this);
                    zzfu.this.zzfn();
                    com.google.android.gms.ads.internal.util.client.zzb.zzaB("Loading HTML in WebView.");
                    zzfu.this.zzoA.loadDataWithBaseURL(com.google.android.gms.ads.internal.zzo.zzbv().zzat(zzfu.this.zzBt.zzzG), zzfu.this.zzBt.zzCI, "text/html", "UTF-8", null);
                }
            }
        });
        zzg(j);
    }
}
