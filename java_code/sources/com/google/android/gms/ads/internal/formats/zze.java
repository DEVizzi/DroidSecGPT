package com.google.android.gms.ads.internal.formats;

import com.google.android.gms.ads.internal.formats.zzg;
import com.google.android.gms.internal.zzck;
import com.google.android.gms.internal.zzcq;
import com.google.android.gms.internal.zzgd;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zze extends zzcq.zza implements zzg.zza {
    private final Object zzqt = new Object();
    private final String zzvh;
    private final List<zzc> zzvi;
    private final String zzvj;
    private final String zzvl;
    private final zza zzvp;
    private zzg zzvq;
    private final zzc zzvr;
    private final String zzvs;

    public zze(String str, List list, String str2, zzc zzcVar, String str3, String str4, zza zzaVar) {
        this.zzvh = str;
        this.zzvi = list;
        this.zzvj = str2;
        this.zzvr = zzcVar;
        this.zzvl = str3;
        this.zzvs = str4;
        this.zzvp = zzaVar;
    }

    @Override // com.google.android.gms.internal.zzcq
    public String getBody() {
        return this.zzvj;
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public String getCustomTemplateId() {
        return "";
    }

    @Override // com.google.android.gms.internal.zzcq
    public List getImages() {
        return this.zzvi;
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public void zza(zzg zzgVar) {
        synchronized (this.zzqt) {
            this.zzvq = zzgVar;
        }
    }

    @Override // com.google.android.gms.internal.zzcq
    public com.google.android.gms.dynamic.zzd zzdD() {
        return com.google.android.gms.dynamic.zze.zzw(this.zzvq);
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public String zzdE() {
        return "1";
    }

    @Override // com.google.android.gms.ads.internal.formats.zzg.zza
    public zza zzdF() {
        return this.zzvp;
    }

    @Override // com.google.android.gms.internal.zzcq
    public zzck zzdG() {
        return this.zzvr;
    }

    @Override // com.google.android.gms.internal.zzcq
    public String zzdH() {
        return this.zzvs;
    }

    @Override // com.google.android.gms.internal.zzcq
    public String zzdx() {
        return this.zzvh;
    }

    @Override // com.google.android.gms.internal.zzcq
    public String zzdz() {
        return this.zzvl;
    }
}
