package com.google.android.gms.internal;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
/* loaded from: classes.dex */
public final class zzio extends zznq<zzio> {
    private final Map<String, Object> zzyn = new HashMap();

    private String zzaM(String str) {
        com.google.android.gms.common.internal.zzu.zzcj(str);
        if (str != null && str.startsWith("&")) {
            str = str.substring(1);
        }
        com.google.android.gms.common.internal.zzu.zzh(str, "Name can not be empty or \"&\"");
        return str;
    }

    public void set(String name, String value) {
        this.zzyn.put(zzaM(name), value);
    }

    public String toString() {
        return zzy(this.zzyn);
    }

    @Override // com.google.android.gms.internal.zznq
    public void zza(zzio zzioVar) {
        com.google.android.gms.common.internal.zzu.zzu(zzioVar);
        zzioVar.zzyn.putAll(this.zzyn);
    }

    public Map<String, Object> zzhv() {
        return Collections.unmodifiableMap(this.zzyn);
    }
}
