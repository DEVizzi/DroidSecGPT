package com.google.android.gms.internal;

import com.google.android.gms.internal.zzdt;
import java.util.Map;
import java.util.concurrent.Future;
@zzgd
/* loaded from: classes.dex */
public final class zzgh {
    private String zzDK;
    private String zzDL;
    zzdt.zzd zzDN;
    zzid zzoA;
    private final Object zzqt = new Object();
    private zzhs<zzgj> zzDM = new zzhs<>();
    public final zzdg zzDO = new zzdg() { // from class: com.google.android.gms.internal.zzgh.1
        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            synchronized (zzgh.this.zzqt) {
                if (zzgh.this.zzDM.isDone()) {
                    return;
                }
                if (zzgh.this.zzDK.equals(map.get("request_id"))) {
                    zzgj zzgjVar = new zzgj(1, map);
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("Invalid " + zzgjVar.getType() + " request error: " + zzgjVar.zzfG());
                    zzgh.this.zzDM.zzf(zzgjVar);
                }
            }
        }
    };
    public final zzdg zzDP = new zzdg() { // from class: com.google.android.gms.internal.zzgh.2
        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            synchronized (zzgh.this.zzqt) {
                if (zzgh.this.zzDM.isDone()) {
                    return;
                }
                zzgj zzgjVar = new zzgj(-2, map);
                if (!zzgh.this.zzDK.equals(zzgjVar.getRequestId())) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC(zzgjVar.getRequestId() + " ==== " + zzgh.this.zzDK);
                    return;
                }
                String url = zzgjVar.getUrl();
                if (url == null) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaC("URL missing in loadAdUrl GMSG.");
                    return;
                }
                if (url.contains("%40mediation_adapters%40")) {
                    String replaceAll = url.replaceAll("%40mediation_adapters%40", zzhg.zza(zzidVar.getContext(), map.get("check_adapters"), zzgh.this.zzDL));
                    zzgjVar.setUrl(replaceAll);
                    com.google.android.gms.ads.internal.util.client.zzb.zzaB("Ad request URL modified to " + replaceAll);
                }
                zzgh.this.zzDM.zzf(zzgjVar);
            }
        }
    };

    public zzgh(String str, String str2) {
        this.zzDL = str2;
        this.zzDK = str;
    }

    public void zzb(zzdt.zzd zzdVar) {
        this.zzDN = zzdVar;
    }

    public void zze(zzid zzidVar) {
        this.zzoA = zzidVar;
    }

    public zzdt.zzd zzfD() {
        return this.zzDN;
    }

    public Future<zzgj> zzfE() {
        return this.zzDM;
    }

    public void zzfF() {
        if (this.zzoA != null) {
            this.zzoA.destroy();
            this.zzoA = null;
        }
    }
}
