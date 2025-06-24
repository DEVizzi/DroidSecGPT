package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzaf;
import com.google.android.gms.internal.zzag;
import java.util.Map;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzaj {
    private static void zza(DataLayer dataLayer, zzaf.zzd zzdVar) {
        for (zzag.zza zzaVar : zzdVar.zzhX) {
            dataLayer.zzen(zzdf.zzg(zzaVar));
        }
    }

    public static void zza(DataLayer dataLayer, zzaf.zzi zziVar) {
        if (zziVar.zziM == null) {
            zzbg.zzaC("supplemental missing experimentSupplemental");
            return;
        }
        zza(dataLayer, zziVar.zziM);
        zzb(dataLayer, zziVar.zziM);
        zzc(dataLayer, zziVar.zziM);
    }

    private static void zzb(DataLayer dataLayer, zzaf.zzd zzdVar) {
        for (zzag.zza zzaVar : zzdVar.zzhW) {
            Map<String, Object> zzc = zzc(zzaVar);
            if (zzc != null) {
                dataLayer.push(zzc);
            }
        }
    }

    private static Map<String, Object> zzc(zzag.zza zzaVar) {
        Object zzl = zzdf.zzl(zzaVar);
        if (zzl instanceof Map) {
            return (Map) zzl;
        }
        zzbg.zzaC("value: " + zzl + " is not a map value, ignored.");
        return null;
    }

    private static void zzc(DataLayer dataLayer, zzaf.zzd zzdVar) {
        zzaf.zzc[] zzcVarArr;
        for (zzaf.zzc zzcVar : zzdVar.zzhY) {
            if (zzcVar.zzaC == null) {
                zzbg.zzaC("GaExperimentRandom: No key");
            } else {
                Object obj = dataLayer.get(zzcVar.zzaC);
                Long valueOf = !(obj instanceof Number) ? null : Long.valueOf(((Number) obj).longValue());
                long j = zzcVar.zzhS;
                long j2 = zzcVar.zzhT;
                if (!zzcVar.zzhU || valueOf == null || valueOf.longValue() < j || valueOf.longValue() > j2) {
                    if (j <= j2) {
                        obj = Long.valueOf(Math.round((Math.random() * (j2 - j)) + j));
                    } else {
                        zzbg.zzaC("GaExperimentRandom: random range invalid");
                    }
                }
                dataLayer.zzen(zzcVar.zzaC);
                Map<String, Object> zzj = dataLayer.zzj(zzcVar.zzaC, obj);
                if (zzcVar.zzhV > 0) {
                    if (zzj.containsKey("gtm")) {
                        Object obj2 = zzj.get("gtm");
                        if (obj2 instanceof Map) {
                            ((Map) obj2).put("lifetime", Long.valueOf(zzcVar.zzhV));
                        } else {
                            zzbg.zzaC("GaExperimentRandom: gtm not a map");
                        }
                    } else {
                        zzj.put("gtm", DataLayer.mapOf("lifetime", Long.valueOf(zzcVar.zzhV)));
                    }
                }
                dataLayer.push(zzj);
            }
        }
    }
}
