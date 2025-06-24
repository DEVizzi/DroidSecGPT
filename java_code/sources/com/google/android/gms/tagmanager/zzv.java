package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzv extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.CUSTOM_VAR.toString();
    private static final String NAME = com.google.android.gms.internal.zzae.NAME.toString();
    private static final String zzaLo = com.google.android.gms.internal.zzae.DEFAULT_VALUE.toString();
    private final DataLayer zzaKz;

    public zzv(DataLayer dataLayer) {
        super(ID, NAME);
        this.zzaKz = dataLayer;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        Object obj = this.zzaKz.get(zzdf.zzg(map.get(NAME)));
        if (obj == null) {
            zzag.zza zzaVar = map.get(zzaLo);
            return zzaVar != null ? zzaVar : zzdf.zzzQ();
        }
        return zzdf.zzI(obj);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return false;
    }
}
