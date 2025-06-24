package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzaw extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.INSTALL_REFERRER.toString();
    private static final String zzaKp = com.google.android.gms.internal.zzae.COMPONENT.toString();
    private final Context zzpH;

    public zzaw(Context context) {
        super(ID, new String[0]);
        this.zzpH = context;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        String zzj = zzax.zzj(this.zzpH, map.get(zzaKp) != null ? zzdf.zzg(map.get(zzaKp)) : null);
        return zzj != null ? zzdf.zzI(zzj) : zzdf.zzzQ();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
