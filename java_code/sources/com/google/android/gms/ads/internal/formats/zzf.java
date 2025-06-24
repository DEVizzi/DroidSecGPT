package com.google.android.gms.ads.internal.formats;

import com.google.android.gms.ads.internal.formats.zzg;
import com.google.android.gms.internal.zzck;
import com.google.android.gms.internal.zzcs;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzkw;
import java.util.Arrays;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzf extends zzcs.zza implements zzg.zza {
    private final Object zzqt = new Object();
    private final zza zzvp;
    private zzg zzvq;
    private final String zzvt;
    private final zzkw<String, zzc> zzvu;
    private final zzkw<String, String> zzvv;

    public zzf(String str, zzkw<String, zzc> zzkwVar, zzkw<String, String> zzkwVar2, zza zzaVar) {
        this.zzvt = str;
        this.zzvu = zzkwVar;
        this.zzvv = zzkwVar2;
        this.zzvp = zzaVar;
    }

    @Override // com.google.android.gms.internal.zzcs
    public List<String> getAvailableAssetNames() {
        int i = 0;
        String[] strArr = new String[this.zzvu.size() + this.zzvv.size()];
        int i2 = 0;
        for (int i3 = 0; i3 < this.zzvu.size(); i3++) {
            strArr[i2] = this.zzvu.keyAt(i3);
            i2++;
        }
        while (i < this.zzvv.size()) {
            strArr[i2] = this.zzvv.keyAt(i);
            i++;
            i2++;
        }
        return Arrays.asList(strArr);
    }

    @Override // com.google.android.gms.internal.zzcs, com.google.android.gms.ads.internal.formats.zzg.zza
    public String getCustomTemplateId() {
        return this.zzvt;
    }

    @Override // com.google.android.gms.internal.zzcs
    public void performClick(String assetName) {
        synchronized (this.zzqt) {
            if (this.zzvq == null) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaz("Attempt to call performClick before ad initialized.");
            } else {
                this.zzvq.performClick(assetName);
            }
        }
    }

    @Override // com.google.android.gms.internal.zzcs
    public void recordImpression() {
        synchronized (this.zzqt) {
            if (this.zzvq == null) {
                com.google.android.gms.ads.internal.util.client.zzb.zzaz("Attempt to perform recordImpression before ad initialized.");
            } else {
                this.zzvq.recordImpression();
            }
        }
    }

    @Override // com.google.android.gms.internal.zzcs
    public String zzQ(String str) {
        return this.zzvv.get(str);
    }

    @Override // com.google.android.gms.internal.zzcs
    public zzck zzR(String str) {
        return this.zzvu.get(str);
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public void zza(zzg zzgVar) {
        synchronized (this.zzqt) {
            this.zzvq = zzgVar;
        }
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public String zzdE() {
        return "3";
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public zza zzdF() {
        return this.zzvp;
    }
}
