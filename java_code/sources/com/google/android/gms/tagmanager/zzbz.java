package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzbz extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.PLATFORM.toString();
    private static final zzag.zza zzaMB = zzdf.zzI("Android");

    public zzbz() {
        super(ID, new String[0]);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        return zzaMB;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
