package com.google.android.gms.internal;
@zzgd
/* loaded from: classes.dex */
public class zzdp extends zzhh {
    final zzid zzoA;
    final zzdr zzwB;
    private final String zzwC;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzdp(zzid zzidVar, String str) {
        this.zzoA = zzidVar;
        this.zzwB = new zzdr(zzidVar);
        this.zzwC = str;
        com.google.android.gms.ads.internal.zzo.zzbH().zza(this);
    }

    @Override // com.google.android.gms.internal.zzhh
    public void onStop() {
        this.zzwB.abort();
    }

    @Override // com.google.android.gms.internal.zzhh
    public void zzdP() {
        try {
            this.zzwB.zzW(this.zzwC);
        } finally {
            zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzdp.1
                @Override // java.lang.Runnable
                public void run() {
                    com.google.android.gms.ads.internal.zzo.zzbH().zzb(zzdp.this);
                }
            });
        }
    }
}
