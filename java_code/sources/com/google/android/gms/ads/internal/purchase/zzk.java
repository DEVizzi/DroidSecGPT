package com.google.android.gms.ads.internal.purchase;

import android.content.Intent;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.internal.zzgd;
@zzgd
/* loaded from: classes.dex */
public class zzk {
    private final String zzsU;

    public zzk(String str) {
        this.zzsU = str;
    }

    public boolean zza(String str, int i, Intent intent) {
        if (str == null || intent == null) {
            return false;
        }
        String zze = zzo.zzbF().zze(intent);
        String zzf = zzo.zzbF().zzf(intent);
        if (zze == null || zzf == null) {
            return false;
        }
        if (!str.equals(zzo.zzbF().zzai(zze))) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Developer payload not match.");
            return false;
        } else if (this.zzsU == null || zzl.zzc(this.zzsU, zze, zzf)) {
            return true;
        } else {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Fail to verify signature.");
            return false;
        }
    }

    public String zzfi() {
        return zzo.zzbv().zzgn();
    }
}
