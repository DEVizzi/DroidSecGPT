package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.List;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzx extends zzdd {
    private static final String ID = com.google.android.gms.internal.zzad.DATA_LAYER_WRITE.toString();
    private static final String VALUE = com.google.android.gms.internal.zzae.VALUE.toString();
    private static final String zzaLz = com.google.android.gms.internal.zzae.CLEAR_PERSISTENT_DATA_LAYER_PREFIX.toString();
    private final DataLayer zzaKz;

    public zzx(DataLayer dataLayer) {
        super(ID, VALUE);
        this.zzaKz = dataLayer;
    }

    private void zza(zzag.zza zzaVar) {
        String zzg;
        if (zzaVar == null || zzaVar == zzdf.zzzK() || (zzg = zzdf.zzg(zzaVar)) == zzdf.zzzP()) {
            return;
        }
        this.zzaKz.zzen(zzg);
    }

    private void zzb(zzag.zza zzaVar) {
        if (zzaVar == null || zzaVar == zzdf.zzzK()) {
            return;
        }
        Object zzl = zzdf.zzl(zzaVar);
        if (zzl instanceof List) {
            for (Object obj : (List) zzl) {
                if (obj instanceof Map) {
                    this.zzaKz.push((Map) obj);
                }
            }
        }
    }

    @Override // com.google.android.gms.tagmanager.zzdd
    public void zzG(Map<String, zzag.zza> map) {
        zzb(map.get(VALUE));
        zza(map.get(zzaLz));
    }
}
