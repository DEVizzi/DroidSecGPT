package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import java.util.HashMap;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzt extends zzak {
    private final zza zzaLe;
    private static final String ID = com.google.android.gms.internal.zzad.FUNCTION_CALL.toString();
    private static final String zzaLd = com.google.android.gms.internal.zzae.FUNCTION_CALL_NAME.toString();
    private static final String zzaKr = com.google.android.gms.internal.zzae.ADDITIONAL_PARAMS.toString();

    /* loaded from: classes.dex */
    public interface zza {
        Object zzd(String str, Map<String, Object> map);
    }

    public zzt(zza zzaVar) {
        super(ID, zzaLd);
        this.zzaLe = zzaVar;
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public zzag.zza zzE(Map<String, zzag.zza> map) {
        String zzg = zzdf.zzg(map.get(zzaLd));
        HashMap hashMap = new HashMap();
        zzag.zza zzaVar = map.get(zzaKr);
        if (zzaVar != null) {
            Object zzl = zzdf.zzl(zzaVar);
            if (!(zzl instanceof Map)) {
                zzbg.zzaC("FunctionCallMacro: expected ADDITIONAL_PARAMS to be a map.");
                return zzdf.zzzQ();
            }
            for (Map.Entry entry : ((Map) zzl).entrySet()) {
                hashMap.put(entry.getKey().toString(), entry.getValue());
            }
        }
        try {
            return zzdf.zzI(this.zzaLe.zzd(zzg, hashMap));
        } catch (Exception e) {
            zzbg.zzaC("Custom macro/tag " + zzg + " threw exception " + e.getMessage());
            return zzdf.zzzQ();
        }
    }

    @Override // com.google.android.gms.tagmanager.zzak
    public boolean zzyh() {
        return false;
    }
}
