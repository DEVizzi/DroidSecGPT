package com.google.android.gms.tagmanager;

import android.os.Build;
import com.google.android.gms.internal.zzag;
import java.util.Map;
/* loaded from: classes.dex */
class zzbx extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.OS_VERSION.toString();

    public zzbx() {
        super(ID, new String[0]);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        return zzdf.zzI(Build.VERSION.RELEASE);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return true;
    }
}
