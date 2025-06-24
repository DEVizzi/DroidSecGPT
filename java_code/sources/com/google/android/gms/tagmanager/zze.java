package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zze extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.ADWORDS_CLICK_REFERRER.toString();
    private static final String zzaKp = com.google.android.gms.internal.zzae.COMPONENT.toString();
    private static final String zzaKq = com.google.android.gms.internal.zzae.CONVERSION_ID.toString();
    private final Context zzpH;

    public zze(Context context) {
        super(ID, zzaKq);
        this.zzpH = context;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        zzag.zza zzaVar = map.get(zzaKq);
        if (zzaVar == null) {
            return zzdf.zzzQ();
        }
        String zzg = zzdf.zzg(zzaVar);
        zzag.zza zzaVar2 = map.get(zzaKp);
        String zzf = zzax.zzf(this.zzpH, zzg, zzaVar2 != null ? zzdf.zzg(zzaVar2) : null);
        return zzf != null ? zzdf.zzI(zzf) : zzdf.zzzQ();
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
