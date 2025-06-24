package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
abstract class zzdd extends zzak {
    public zzdd(String str, String... strArr) {
        super(str, strArr);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        zzG(map);
        return zzdf.zzzQ();
    }

    public abstract void zzG(Map<String, zzag.zza> map);

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return false;
    }
}
