package com.google.android.gms.internal;

import com.google.android.gms.internal.zznr;
import java.util.ArrayList;
import java.util.List;
/* loaded from: classes.dex */
public abstract class zznr<T extends zznr> {
    private final zzns zzaEe;
    protected final zzno zzaEf;
    private final List<zznp> zzaEg;

    /* JADX INFO: Access modifiers changed from: protected */
    public zznr(zzns zznsVar, zzlb zzlbVar) {
        com.google.android.gms.common.internal.zzu.zzu(zznsVar);
        this.zzaEe = zznsVar;
        this.zzaEg = new ArrayList();
        zzno zznoVar = new zzno(this, zzlbVar);
        zznoVar.zzvZ();
        this.zzaEf = zznoVar;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zza(zzno zznoVar) {
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void zzd(zzno zznoVar) {
        for (zznp zznpVar : this.zzaEg) {
            zznpVar.zza(this, zznoVar);
        }
    }

    public zzno zzhc() {
        zzno zzvP = this.zzaEf.zzvP();
        zzd(zzvP);
        return zzvP;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public zzns zzvX() {
        return this.zzaEe;
    }

    public zzno zzwa() {
        return this.zzaEf;
    }

    public List<zznu> zzwb() {
        return this.zzaEf.zzvR();
    }
}
