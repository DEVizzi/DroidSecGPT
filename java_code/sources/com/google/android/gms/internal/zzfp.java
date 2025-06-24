package com.google.android.gms.internal;

import android.content.Context;
import android.os.SystemClock;
import com.google.android.gms.internal.zzfs;
import com.google.android.gms.internal.zzft;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzie;
@zzgd
/* loaded from: classes.dex */
public abstract class zzfp extends zzfs implements zzie.zza {
    private final zzie zzBd;
    protected boolean zzBe;
    private boolean zzxo;

    /* JADX INFO: Access modifiers changed from: protected */
    public zzfp(Context context, zzha.zza zzaVar, zzid zzidVar, zzft.zza zzaVar2) {
        super(context, zzaVar, zzidVar, zzaVar2);
        this.zzBe = false;
        this.zzxo = false;
        this.zzBd = zzidVar.zzgF();
    }

    private boolean zze(long j) throws zzfs.zza {
        long elapsedRealtime = 60000 - (SystemClock.elapsedRealtime() - j);
        if (elapsedRealtime <= 1) {
            return false;
        }
        try {
            this.zzqt.wait(elapsedRealtime);
            return true;
        } catch (InterruptedException e) {
            throw new zzfs.zza("Ad request cancelled.", -1);
        }
    }

    @Override // com.google.android.gms.internal.zzfs, com.google.android.gms.internal.zzhh
    public void onStop() {
        synchronized (this.zzBr) {
            this.zzoA.stopLoading();
            com.google.android.gms.ads.internal.zzo.zzbx().zza(this.zzoA.getWebView());
        }
    }

    @Override // com.google.android.gms.internal.zzie.zza
    public void zza(zzid zzidVar, boolean z) {
        synchronized (this.zzqt) {
            com.google.android.gms.ads.internal.util.client.zzb.zzay("WebView finished loading.");
            this.zzBe = true;
            this.zzxo = z ? false : true;
            this.zzqt.notify();
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zzg(long j) throws zzfs.zza {
        while (zze(j)) {
            if (this.zzxo) {
                throw new zzfs.zza("Received cancellation request from creative.", 0);
            }
            if (this.zzBe) {
                return;
            }
        }
        throw new zzfs.zza("Timed out waiting for WebView to finish loading.", 2);
    }
}
