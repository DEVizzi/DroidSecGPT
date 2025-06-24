package com.google.android.gms.analytics.internal;

import com.google.android.gms.internal.zznx;
/* loaded from: classes.dex */
public class zzk extends zzd {
    private final zznx zzKm;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzk(zzf zzfVar) {
        super(zzfVar);
        this.zzKm = new zznx();
    }

    public void zzhi() {
        zzan zzhm = zzhm();
        String zzjL = zzhm.zzjL();
        if (zzjL != null) {
            this.zzKm.setAppName(zzjL);
        }
        String zzjN = zzhm.zzjN();
        if (zzjN != null) {
            this.zzKm.setAppVersion(zzjN);
        }
    }

    @Override // com.google.android.gms.analytics.internal.zzd
    protected void zzhn() {
        zzhS().zzwc().zza(this.zzKm);
        zzhi();
    }

    public zznx zzix() {
        zzia();
        return this.zzKm;
    }
}
