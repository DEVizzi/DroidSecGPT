package com.google.android.gms.internal;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public final class zzno {
    private final zznr zzaDU;
    private boolean zzaDV;
    private long zzaDW;
    private long zzaDX;
    private long zzaDY;
    private long zzaDZ;
    private long zzaEa;
    private boolean zzaEb;
    private final Map<Class<? extends zznq>, zznq> zzaEc;
    private final List<zznu> zzaEd;
    private final zzlb zzpw;

    zzno(zzno zznoVar) {
        this.zzaDU = zznoVar.zzaDU;
        this.zzpw = zznoVar.zzpw;
        this.zzaDW = zznoVar.zzaDW;
        this.zzaDX = zznoVar.zzaDX;
        this.zzaDY = zznoVar.zzaDY;
        this.zzaDZ = zznoVar.zzaDZ;
        this.zzaEa = zznoVar.zzaEa;
        this.zzaEd = new ArrayList(zznoVar.zzaEd);
        this.zzaEc = new HashMap(zznoVar.zzaEc.size());
        for (Map.Entry<Class<? extends zznq>, zznq> entry : zznoVar.zzaEc.entrySet()) {
            zznq zzf = zzf(entry.getKey());
            entry.getValue().zza(zzf);
            this.zzaEc.put(entry.getKey(), zzf);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzno(zznr zznrVar, zzlb zzlbVar) {
        com.google.android.gms.common.internal.zzu.zzu(zznrVar);
        com.google.android.gms.common.internal.zzu.zzu(zzlbVar);
        this.zzaDU = zznrVar;
        this.zzpw = zzlbVar;
        this.zzaDZ = 1800000L;
        this.zzaEa = 3024000000L;
        this.zzaEc = new HashMap();
        this.zzaEd = new ArrayList();
    }

    private static <T extends zznq> T zzf(Class<T> cls) {
        try {
            return cls.newInstance();
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("dataType default constructor is not accessible", e);
        } catch (InstantiationException e2) {
            throw new IllegalArgumentException("dataType doesn't have default constructor", e2);
        }
    }

    public void zzL(long j) {
        this.zzaDX = j;
    }

    public void zzb(zznq zznqVar) {
        com.google.android.gms.common.internal.zzu.zzu(zznqVar);
        Class<?> cls = zznqVar.getClass();
        if (cls.getSuperclass() != zznq.class) {
            throw new IllegalArgumentException();
        }
        zznqVar.zza(zze(cls));
    }

    public <T extends zznq> T zzd(Class<T> cls) {
        return (T) this.zzaEc.get(cls);
    }

    public <T extends zznq> T zze(Class<T> cls) {
        T t = (T) this.zzaEc.get(cls);
        if (t == null) {
            T t2 = (T) zzf(cls);
            this.zzaEc.put(cls, t2);
            return t2;
        }
        return t;
    }

    public zzno zzvP() {
        return new zzno(this);
    }

    public Collection<zznq> zzvQ() {
        return this.zzaEc.values();
    }

    public List<zznu> zzvR() {
        return this.zzaEd;
    }

    public long zzvS() {
        return this.zzaDW;
    }

    public void zzvT() {
        zzvX().zze(this);
    }

    public boolean zzvU() {
        return this.zzaDV;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzvV() {
        this.zzaDY = this.zzpw.elapsedRealtime();
        if (this.zzaDX != 0) {
            this.zzaDW = this.zzaDX;
        } else {
            this.zzaDW = this.zzpw.currentTimeMillis();
        }
        this.zzaDV = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public zznr zzvW() {
        return this.zzaDU;
    }

    zzns zzvX() {
        return this.zzaDU.zzvX();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean zzvY() {
        return this.zzaEb;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzvZ() {
        this.zzaEb = true;
    }
}
