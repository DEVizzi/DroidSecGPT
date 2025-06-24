package com.google.android.gms.internal;

import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzds implements zzdg {
    @Override // com.google.android.gms.internal.zzdg
    public void zza(zzid zzidVar, Map<String, String> map) {
        zzdq zzbH = com.google.android.gms.ads.internal.zzo.zzbH();
        if (map.containsKey("abort")) {
            if (zzbH.zza(zzidVar)) {
                return;
            }
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Precache abort but no preload task running.");
            return;
        }
        String str = map.get("src");
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Precache video action is missing the src parameter.");
        } else if (zzbH.zzb(zzidVar)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Precache task already running.");
        } else {
            new zzdp(zzidVar, str).zzgi();
        }
    }
}
