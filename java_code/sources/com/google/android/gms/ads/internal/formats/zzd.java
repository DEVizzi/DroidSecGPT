package com.google.android.gms.ads.internal.formats;

import com.google.android.gms.ads.internal.formats.zzg;
import com.google.android.gms.internal.zzck;
import com.google.android.gms.internal.zzco;
import com.google.android.gms.internal.zzgd;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzd extends zzco.zza implements zzg.zza {
    private final Object zzqt = new Object();
    private final String zzvh;
    private final List<zzc> zzvi;
    private final String zzvj;
    private final zzc zzvk;
    private final String zzvl;
    private final double zzvm;
    private final String zzvn;
    private final String zzvo;
    private final zza zzvp;
    private zzg zzvq;

    public zzd(String str, List list, String str2, zzc zzcVar, String str3, double d, String str4, String str5, zza zzaVar) {
        this.zzvh = str;
        this.zzvi = list;
        this.zzvj = str2;
        this.zzvk = zzcVar;
        this.zzvl = str3;
        this.zzvm = d;
        this.zzvn = str4;
        this.zzvo = str5;
        this.zzvp = zzaVar;
    }

    @Override // com.google.android.gms.internal.zzco
    public String getBody() {
        return this.zzvj;
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public String getCustomTemplateId() {
        return "";
    }

    @Override // com.google.android.gms.internal.zzco
    public List getImages() {
        return this.zzvi;
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public void zza(zzg zzgVar) {
        synchronized (this.zzqt) {
            this.zzvq = zzgVar;
        }
    }

    @Override // com.google.android.gms.internal.zzco
    public double zzdA() {
        return this.zzvm;
    }

    @Override // com.google.android.gms.internal.zzco
    public String zzdB() {
        return this.zzvn;
    }

    @Override // com.google.android.gms.internal.zzco
    public String zzdC() {
        return this.zzvo;
    }

    @Override // com.google.android.gms.internal.zzco
    public com.google.android.gms.dynamic.zzd zzdD() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzvq);
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public String zzdE() {
        return "2";
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public zza zzdF() {
        return this.zzvp;
    }

    @Override // com.google.android.gms.internal.zzco
    public String zzdx() {
        return this.zzvh;
    }

    @Override // com.google.android.gms.internal.zzco
    public zzck zzdy() {
        return this.zzvk;
    }

    @Override // com.google.android.gms.internal.zzco
    public String zzdz() {
        return this.zzvl;
    }
}
