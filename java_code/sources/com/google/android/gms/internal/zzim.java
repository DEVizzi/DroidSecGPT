package com.google.android.gms.internal;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public final class zzim extends zznq<zzim> {
    private Map<Integer, String> zzJa = new HashMap(4);

    public String toString() {
        HashMap hashMap = new HashMap();
        for (Map.Entry<Integer, String> entry : this.zzJa.entrySet()) {
            hashMap.put("dimension" + entry.getKey(), entry.getValue());
        }
        return zzy(hashMap);
    }

    @Override // com.google.android.gms.internal.zznq
    public void zza(zzim zzimVar) {
        zzimVar.zzJa.putAll(this.zzJa);
    }

    public Map<Integer, String> zzht() {
        return Collections.unmodifiableMap(this.zzJa);
    }
}
