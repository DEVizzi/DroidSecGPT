package com.google.android.gms.internal;

import android.view.View;
import com.google.android.gms.internal.zzch;
@zzgd
/* loaded from: classes.dex */
public final class zzcf extends zzch.zza {
    private final com.google.android.gms.ads.internal.zzf zzuS;
    private final String zzuT;
    private final String zzuU;

    public zzcf(com.google.android.gms.ads.internal.zzf zzfVar, String str, String str2) {
        this.zzuS = zzfVar;
        this.zzuT = str;
        this.zzuU = str2;
    }

    @Override // com.google.android.gms.internal.zzch
    public String getContent() {
        return this.zzuU;
    }

    @Override // com.google.android.gms.internal.zzch
    public void recordClick() {
        this.zzuS.recordClick();
    }

    @Override // com.google.android.gms.internal.zzch
    public void recordImpression() {
        this.zzuS.recordImpression();
    }

    @Override // com.google.android.gms.internal.zzch
    public void zza(com.google.android.gms.dynamic.zzd zzdVar) {
        if (zzdVar == null) {
            return;
        }
        this.zzuS.zzc((View) com.google.android.gms.dynamic.zze.zzn(zzdVar));
    }

    @Override // com.google.android.gms.internal.zzch
    public String zzdt() {
        return this.zzuT;
    }
}
