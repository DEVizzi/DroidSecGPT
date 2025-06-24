package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzr extends zzcz {
    private static final String ID = com.google.android.gms.internal.zzad.CONTAINS.toString();

    public zzr() {
        super(ID);
    }

    @Override // com.google.android.gms.tagmanager.zzcz
    protected boolean zza(String str, String str2, Map<String, zzag.zza> map) {
        return str.contains(str2);
    }
}
