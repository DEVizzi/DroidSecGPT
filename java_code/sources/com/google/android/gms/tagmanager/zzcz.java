package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
abstract class zzcz extends zzca {
    public zzcz(String str) {
        super(str);
    }

    @Override // com.google.android.gms.tagmanager.zzca
    protected boolean zza(zzag.zza zzaVar, zzag.zza zzaVar2, Map<String, zzag.zza> map) {
        String zzg = zzdf.zzg(zzaVar);
        String zzg2 = zzdf.zzg(zzaVar2);
        if (zzg == zzdf.zzzP() || zzg2 == zzdf.zzzP()) {
            return false;
        }
        return zza(zzg, zzg2, map);
    }

    protected abstract boolean zza(String str, String str2, Map<String, zzag.zza> map);
}
