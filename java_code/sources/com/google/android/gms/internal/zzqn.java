package com.google.android.gms.internal;

import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.zzqe;
import com.google.android.gms.internal.zzqf;
/* loaded from: classes.dex */
public abstract class zzqn {
    private zzqd zzaPU;
    private zzqb zzaPV;
    private zzlb zzpw;

    /* loaded from: classes.dex */
    public enum zza {
        NOT_AVAILABLE,
        IO_ERROR,
        SERVER_ERROR
    }

    /* loaded from: classes.dex */
    public class zzb {
        private final zzqe.zza.EnumC0156zza zzaPp;
        private final long zzaPr;
        private final Object zzaQa;

        public Object zzAH() {
            return this.zzaQa;
        }

        public zzqe.zza.EnumC0156zza zzAh() {
            return this.zzaPp;
        }

        public long zzAl() {
            return this.zzaPr;
        }
    }

    public zzqn(zzqd zzqdVar, zzqb zzqbVar) {
        this(zzqdVar, zzqbVar, zzld.zzoQ());
    }

    public zzqn(zzqd zzqdVar, zzqb zzqbVar, zzlb zzlbVar) {
        com.google.android.gms.common.internal.zzu.zzV(zzqdVar.zzAf().size() == 1);
        this.zzaPU = zzqdVar;
        this.zzaPV = zzqbVar;
        this.zzpw = zzlbVar;
    }

    protected abstract zzb zza(zzpy zzpyVar);

    protected abstract void zza(zzqe zzqeVar);

    public void zza(zza zzaVar) {
        com.google.android.gms.tagmanager.zzbg.zzaz("ResourceManager: Failed to download a resource: " + zzaVar.name());
        zzpy zzpyVar = this.zzaPU.zzAf().get(0);
        zzb zza2 = zza(zzpyVar);
        zza(new zzqe((zza2 == null || !(zza2.zzAH() instanceof zzqf.zzc)) ? new zzqe.zza(Status.zzXR, zzpyVar, zzqe.zza.EnumC0156zza.NETWORK) : new zzqe.zza(Status.zzXP, zzpyVar, null, (zzqf.zzc) zza2.zzAH(), zza2.zzAh(), zza2.zzAl())));
    }

    public void zzu(byte[] bArr) {
        long j;
        zzqe.zza.EnumC0156zza enumC0156zza;
        Object obj;
        com.google.android.gms.tagmanager.zzbg.zzaB("ResourceManager: Resource downloaded from Network: " + this.zzaPU.getId());
        zzpy zzpyVar = this.zzaPU.zzAf().get(0);
        zzqe.zza.EnumC0156zza enumC0156zza2 = zzqe.zza.EnumC0156zza.NETWORK;
        Object obj2 = null;
        try {
            obj2 = this.zzaPV.zzt(bArr);
            long currentTimeMillis = this.zzpw.currentTimeMillis();
            if (obj2 == null) {
                com.google.android.gms.tagmanager.zzbg.zzaA("Parsed resource from network is null");
                zzb zza2 = zza(zzpyVar);
                if (zza2 != null) {
                    obj2 = zza2.zzAH();
                    enumC0156zza2 = zza2.zzAh();
                    currentTimeMillis = zza2.zzAl();
                }
            }
            j = currentTimeMillis;
            enumC0156zza = enumC0156zza2;
            obj = obj2;
        } catch (zzqf.zzg e) {
            com.google.android.gms.tagmanager.zzbg.zzaA("Resource from network is corrupted");
            zzb zza3 = zza(zzpyVar);
            if (zza3 != null) {
                Object zzAH = zza3.zzAH();
                j = 0;
                enumC0156zza = zza3.zzAh();
                obj = zzAH;
            } else {
                j = 0;
                enumC0156zza = enumC0156zza2;
                obj = obj2;
            }
        }
        zza(new zzqe(obj != null ? new zzqe.zza(Status.zzXP, zzpyVar, bArr, (zzqf.zzc) obj, enumC0156zza, j) : new zzqe.zza(Status.zzXR, zzpyVar, zzqe.zza.EnumC0156zza.NETWORK)));
    }
}
