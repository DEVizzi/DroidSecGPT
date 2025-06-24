package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzbc extends zzbv {
    private static final String ID = com.google.android.gms.internal.zzad.LESS_EQUALS.toString();

    public zzbc() {
        super(ID);
    }

    @Override // com.google.android.gms.tagmanager.zzbv
    protected boolean zza(zzde zzdeVar, zzde zzdeVar2, Map<String, zzag.zza> map) {
        return zzdeVar.compareTo(zzdeVar2) <= 0;
    }
}
