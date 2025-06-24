package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzae extends zzcz {
    private static final String ID = com.google.android.gms.internal.zzad.ENDS_WITH.toString();

    public zzae() {
        super(ID);
    }

    @Override // com.google.android.gms.tagmanager.zzcz
    protected boolean zza(String str, String str2, Map<String, zzag.zza> map) {
        return str.endsWith(str2);
    }
}
