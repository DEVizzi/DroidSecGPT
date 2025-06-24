package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.internal.zzag;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzb extends zzak {
    private static final String ID = com.google.android.gms.internal.zzad.ADVERTISER_ID.toString();
    private final zza zzaKo;

    public zzb(Context context) {
        this(zza.zzaE(context));
    }

    zzb(zza zzaVar) {
        super(ID, new String[0]);
        this.zzaKo = zzaVar;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        String zzyd = this.zzaKo.zzyd();
        return zzyd == null ? zzdf.zzzQ() : zzdf.zzI(zzyd);
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return false;
    }
}
