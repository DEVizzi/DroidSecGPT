package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
abstract class zzbv extends zzca {
    public zzbv(String str) {
        super(str);
    }

    @Override // com.google.android.gms.tagmanager.zzca
    protected boolean zza(zzag.zza zzaVar, zzag.zza zzaVar2, Map<String, zzag.zza> map) {
        zzde zzh = zzdf.zzh(zzaVar);
        zzde zzh2 = zzdf.zzh(zzaVar2);
        if (zzh == zzdf.zzzO() || zzh2 == zzdf.zzzO()) {
            return false;
        }
        return zza(zzh, zzh2, map);
    }

    protected abstract boolean zza(zzde zzdeVar, zzde zzdeVar2, Map<String, zzag.zza> map);
}
