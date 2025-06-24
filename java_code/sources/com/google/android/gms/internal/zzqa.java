package com.google.android.gms.internal;

import android.content.Context;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.zzqe;
import com.google.android.gms.internal.zzqf;
import com.google.android.gms.internal.zzqn;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
/* loaded from: classes.dex */
public class zzqa {
    private final Context mContext;
    private String zzaLc;
    private final zzqh zzaPe;
    Map<String, zzc<zzqf.zzc>> zzaPf;
    private final Map<String, zzqp> zzaPg;
    private final zzlb zzpw;

    /* loaded from: classes.dex */
    public interface zza {
        void zza(zzqe zzqeVar);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class zzb extends zzqn {
        private final zza zzaPk;

        zzb(zzqd zzqdVar, zzqb zzqbVar, zza zzaVar) {
            super(zzqdVar, zzqbVar);
            this.zzaPk = zzaVar;
        }

        @Override // com.google.android.gms.internal.zzqn
        protected zzqn.zzb zza(zzpy zzpyVar) {
            return null;
        }

        @Override // com.google.android.gms.internal.zzqn
        protected void zza(zzqe zzqeVar) {
            zzqe.zza zzAg = zzqeVar.zzAg();
            zzqa.this.zza(zzAg);
            if (zzAg.getStatus() == Status.zzXP && zzAg.zzAh() == zzqe.zza.EnumC0156zza.NETWORK && zzAg.zzAi() != null && zzAg.zzAi().length > 0) {
                zzqa.this.zzaPe.zze(zzAg.zzAj().zzAb(), zzAg.zzAi());
                com.google.android.gms.tagmanager.zzbg.zzaB("Resource successfully load from Network.");
                this.zzaPk.zza(zzqeVar);
                return;
            }
            com.google.android.gms.tagmanager.zzbg.zzaB("Response status: " + (zzAg.getStatus().isSuccess() ? "SUCCESS" : "FAILURE"));
            if (zzAg.getStatus().isSuccess()) {
                com.google.android.gms.tagmanager.zzbg.zzaB("Response source: " + zzAg.zzAh().toString());
                com.google.android.gms.tagmanager.zzbg.zzaB("Response size: " + zzAg.zzAi().length);
            }
            zzqa.this.zza(zzAg.zzAj(), this.zzaPk);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class zzc<T> {
        private T mData;
        private Status zzOt;
        private long zzaPl;

        public zzc(Status status, T t, long j) {
            this.zzOt = status;
            this.mData = t;
            this.zzaPl = j;
        }

        public long zzAe() {
            return this.zzaPl;
        }

        public void zzO(T t) {
            this.mData = t;
        }

        public void zzU(long j) {
            this.zzaPl = j;
        }

        public void zzaV(Status status) {
            this.zzOt = status;
        }
    }

    public zzqa(Context context) {
        this(context, new HashMap(), new zzqh(context), zzld.zzoQ());
    }

    zzqa(Context context, Map<String, zzqp> map, zzqh zzqhVar, zzlb zzlbVar) {
        this.zzaLc = null;
        this.zzaPf = new HashMap();
        this.mContext = context;
        this.zzpw = zzlbVar;
        this.zzaPe = zzqhVar;
        this.zzaPg = map;
    }

    private void zza(zzqd zzqdVar, zza zzaVar) {
        List<zzpy> zzAf = zzqdVar.zzAf();
        com.google.android.gms.common.internal.zzu.zzV(zzAf.size() == 1);
        zza(zzAf.get(0), zzaVar);
    }

    void zza(final zzpy zzpyVar, final zza zzaVar) {
        this.zzaPe.zza(zzpyVar.zzAb(), zzpyVar.zzzZ(), zzqc.zzaPm, new zzqg() { // from class: com.google.android.gms.internal.zzqa.1
            @Override // com.google.android.gms.internal.zzqg
            public void zza(Status status, Object obj, Integer num, long j) {
                zzqe.zza zzaVar2;
                if (status.isSuccess()) {
                    zzaVar2 = new zzqe.zza(Status.zzXP, zzpyVar, null, (zzqf.zzc) obj, num == zzqh.zzaPM ? zzqe.zza.EnumC0156zza.DEFAULT : zzqe.zza.EnumC0156zza.DISK, j);
                } else {
                    zzaVar2 = new zzqe.zza(new Status(16, "There is no valid resource for the container: " + zzpyVar.getContainerId()), null, zzqe.zza.EnumC0156zza.DISK);
                }
                zzaVar.zza(new zzqe(zzaVar2));
            }
        });
    }

    void zza(zzqd zzqdVar, zza zzaVar, zzqn zzqnVar) {
        boolean z;
        zzqp zzqpVar;
        boolean z2 = false;
        Iterator<zzpy> it = zzqdVar.zzAf().iterator();
        while (true) {
            z = z2;
            if (!it.hasNext()) {
                break;
            }
            zzpy next = it.next();
            zzc<zzqf.zzc> zzcVar = this.zzaPf.get(next.getContainerId());
            z2 = (zzcVar != null ? zzcVar.zzAe() : this.zzaPe.zzfa(next.getContainerId())) + 900000 < this.zzpw.currentTimeMillis() ? true : z;
        }
        if (!z) {
            zza(zzqdVar, zzaVar);
            return;
        }
        zzqp zzqpVar2 = this.zzaPg.get(zzqdVar.getId());
        if (zzqpVar2 == null) {
            zzqp zzqpVar3 = this.zzaLc == null ? new zzqp() : new zzqp(this.zzaLc);
            this.zzaPg.put(zzqdVar.getId(), zzqpVar3);
            zzqpVar = zzqpVar3;
        } else {
            zzqpVar = zzqpVar2;
        }
        zzqpVar.zza(this.mContext, zzqdVar, 0L, zzqnVar);
    }

    void zza(zzqe.zza zzaVar) {
        String containerId = zzaVar.zzAj().getContainerId();
        Status status = zzaVar.getStatus();
        zzqf.zzc zzAk = zzaVar.zzAk();
        if (!this.zzaPf.containsKey(containerId)) {
            this.zzaPf.put(containerId, new zzc<>(status, zzAk, this.zzpw.currentTimeMillis()));
            return;
        }
        zzc<zzqf.zzc> zzcVar = this.zzaPf.get(containerId);
        zzcVar.zzU(this.zzpw.currentTimeMillis());
        if (status == Status.zzXP) {
            zzcVar.zzaV(status);
            zzcVar.zzO(zzAk);
        }
    }

    public void zza(String str, Integer num, String str2, zza zzaVar) {
        zzqd zzb2 = new zzqd().zzb(new zzpy(str, num, str2, false));
        zza(zzb2, zzaVar, new zzb(zzb2, zzqc.zzaPm, zzaVar));
    }

    public void zzeU(String str) {
        this.zzaLc = str;
    }
}
