package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public abstract class zzca extends zzak {
    private static final String zzaLE = com.google.android.gms.internal.zzae.ARG0.toString();
    private static final String zzaMC = com.google.android.gms.internal.zzae.ARG1.toString();

    public zzca(String str) {
        super(str, zzaLE, zzaMC);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        for (zzag.zza zzaVar : map.values()) {
            if (zzaVar == zzdf.zzzQ()) {
                return zzdf.zzI(false);
            }
        }
        zzag.zza zzaVar2 = map.get(zzaLE);
        zzag.zza zzaVar3 = map.get(zzaMC);
        return zzdf.zzI(Boolean.valueOf((zzaVar2 == null || zzaVar3 == null) ? false : zza(zzaVar2, zzaVar3, map)));
    }

    protected abstract boolean zza(zzag.zza zzaVar, zzag.zza zzaVar2, Map<String, zzag.zza> map);

    @Override // com.google.android.gms.tagmanager.zzak
    public /* bridge */ /* synthetic */ String zzyM() {
        return super.zzyM();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public /* bridge */ /* synthetic */ Set zzyN() {
        return super.zzyN();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
