package com.google.android.gms.internal;

import java.util.Map;
@zzgd
/* loaded from: classes.dex */
public class zzdj implements zzdg {
    private final zzdk zzwu;

    public zzdj(zzdk zzdkVar) {
        this.zzwu = zzdkVar;
    }

    @Override // com.google.android.gms.internal.zzdg
    public void zza(zzid zzidVar, Map<String, String> map) {
        this.zzwu.zzd("1".equals(map.get("transparentBackground")));
    }
}
