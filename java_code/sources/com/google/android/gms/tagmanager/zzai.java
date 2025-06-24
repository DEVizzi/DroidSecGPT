package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzai extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.EVENT.toString();
    private final zzcp zzaKA;

    public zzai(zzcp zzcpVar) {
        super(ID, new String[0]);
        this.zzaKA = zzcpVar;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        String zzzp = this.zzaKA.zzzp();
        return zzzp == null ? zzdf.zzzQ() : zzdf.zzI(zzzp);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return false;
    }
}
