package com.google.android.gms.internal;

import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public final class zzdd implements zzdg {
    private final zzde zzvU;

    public zzdd(zzde zzdeVar) {
        this.zzvU = zzdeVar;
    }

    @Override // com.google.android.gms.internal.zzdg
    public void zza(zzid zzidVar, Map<String, String> map) {
        String str = map.get("name");
        if (str == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("App event with no name parameter.");
        } else {
            this.zzvU.onAppEvent(str, map.get("info"));
        }
    }
}
