package com.google.android.gms.tagmanager;

import android.content.Context;
import android.os.Looper;
import com.google.android.gms.common.api.AbstractPendingResult;
import com.google.android.gms.common.api.Releasable;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.zzaf;
import com.google.android.gms.internal.zzlb;
import com.google.android.gms.internal.zzld;
import com.google.android.gms.internal.zzpx;
import com.google.android.gms.internal.zzqa;
import com.google.android.gms.internal.zzqe;
import com.google.android.gms.internal.zzqf;
import com.google.android.gms.tagmanager.zzbf;
import com.google.android.gms.tagmanager.zzcb;
import com.google.android.gms.tagmanager.zzo;
/* loaded from: classes.dex */
public class zzp extends AbstractPendingResult<ContainerHolder> {
    private final Context mContext;
    private final Looper zzWt;
    private long zzaKD;
    private final TagManager zzaKK;
    private final zzd zzaKN;
    private final zzcd zzaKO;
    private final int zzaKP;
    private zzf zzaKQ;
    private zzqa zzaKR;
    private volatile zzo zzaKS;
    private volatile boolean zzaKT;
    private zzaf.zzj zzaKU;
    private String zzaKV;
    private zze zzaKW;
    private zza zzaKX;
    private final String zzaKy;
    private final zzlb zzpw;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zza {
        boolean zzb(Container container);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzb implements zzbf<zzpx.zza> {
        private zzb() {
        }

        @Override // com.google.android.gms.tagmanager.zzbf
        /* renamed from: zza */
        public void zzz(zzpx.zza zzaVar) {
            zzaf.zzj zzjVar;
            if (zzaVar.zzaPa != null) {
                zzjVar = zzaVar.zzaPa;
            } else {
                zzaf.zzf zzfVar = zzaVar.zziO;
                zzjVar = new zzaf.zzj();
                zzjVar.zziO = zzfVar;
                zzjVar.zziN = null;
                zzjVar.zziP = zzfVar.version;
            }
            zzp.this.zza(zzjVar, zzaVar.zzaOZ, true);
        }

        @Override // com.google.android.gms.tagmanager.zzbf
        public void zza(zzbf.zza zzaVar) {
            if (zzp.this.zzaKT) {
                return;
            }
            zzp.this.zzR(0L);
        }

        @Override // com.google.android.gms.tagmanager.zzbf
        public void zzyv() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzc implements zzbf<zzaf.zzj> {
        private zzc() {
        }

        @Override // com.google.android.gms.tagmanager.zzbf
        public void zza(zzbf.zza zzaVar) {
            synchronized (zzp.this) {
                if (!zzp.this.isReady()) {
                    if (zzp.this.zzaKS != null) {
                        zzp.this.setResult(zzp.this.zzaKS);
                    } else {
                        zzp.this.setResult(zzp.this.createFailedResult(Status.zzXS));
                    }
                }
            }
            zzp.this.zzR(3600000L);
        }

        @Override // com.google.android.gms.tagmanager.zzbf
        /* renamed from: zzb */
        public void zzz(zzaf.zzj zzjVar) {
            synchronized (zzp.this) {
                if (zzjVar.zziO == null) {
                    if (zzp.this.zzaKU.zziO == null) {
                        zzbg.zzaz("Current resource is null; network resource is also null");
                        zzp.this.zzR(3600000L);
                        return;
                    }
                    zzjVar.zziO = zzp.this.zzaKU.zziO;
                }
                zzp.this.zza(zzjVar, zzp.this.zzpw.currentTimeMillis(), false);
                zzbg.zzaB("setting refresh time to current time: " + zzp.this.zzaKD);
                if (!zzp.this.zzyu()) {
                    zzp.this.zza(zzjVar);
                }
            }
        }

        @Override // com.google.android.gms.tagmanager.zzbf
        public void zzyv() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public class zzd implements zzo.zza {
        private zzd() {
        }

        @Override // com.google.android.gms.tagmanager.zzo.zza
        public void zzej(String str) {
            zzp.this.zzej(str);
        }

        @Override // com.google.android.gms.tagmanager.zzo.zza
        public String zzyo() {
            return zzp.this.zzyo();
        }

        @Override // com.google.android.gms.tagmanager.zzo.zza
        public void zzyq() {
            if (zzp.this.zzaKO.zzkb()) {
                zzp.this.zzR(0L);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zze extends Releasable {
        void zza(zzbf<zzaf.zzj> zzbfVar);

        void zzem(String str);

        void zzf(long j, String str);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zzf extends Releasable {
        void zza(zzbf<zzpx.zza> zzbfVar);

        void zzb(zzpx.zza zzaVar);

        zzqf.zzc zziR(int i);

        void zzyw();
    }

    zzp(Context context, TagManager tagManager, Looper looper, String str, int i, zzf zzfVar, zze zzeVar, zzqa zzqaVar, zzlb zzlbVar, zzcd zzcdVar) {
        super(looper == null ? Looper.getMainLooper() : looper);
        this.mContext = context;
        this.zzaKK = tagManager;
        this.zzWt = looper == null ? Looper.getMainLooper() : looper;
        this.zzaKy = str;
        this.zzaKP = i;
        this.zzaKQ = zzfVar;
        this.zzaKW = zzeVar;
        this.zzaKR = zzqaVar;
        this.zzaKN = new zzd();
        this.zzaKU = new zzaf.zzj();
        this.zzpw = zzlbVar;
        this.zzaKO = zzcdVar;
        if (zzyu()) {
            zzej(zzcb.zzzf().zzzh());
        }
    }

    public zzp(Context context, TagManager tagManager, Looper looper, String str, int i, zzs zzsVar) {
        this(context, tagManager, looper, str, i, new zzcn(context, str), new zzcm(context, str, zzsVar), new zzqa(context), zzld.zzoQ(), new zzbe(30, 900000L, 5000L, "refreshing", zzld.zzoQ()));
        this.zzaKR.zzeU(zzsVar.zzyx());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public synchronized void zzR(long j) {
        if (this.zzaKW == null) {
            zzbg.zzaC("Refresh requested, but no network load scheduler.");
        } else {
            this.zzaKW.zzf(j, this.zzaKU.zziP);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public synchronized void zza(zzaf.zzj zzjVar) {
        if (this.zzaKQ != null) {
            zzpx.zza zzaVar = new zzpx.zza();
            zzaVar.zzaOZ = this.zzaKD;
            zzaVar.zziO = new zzaf.zzf();
            zzaVar.zzaPa = zzjVar;
            this.zzaKQ.zzb(zzaVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Code restructure failed: missing block: B:6:0x0008, code lost:
        if (r8.zzaKT != false) goto L13;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public synchronized void zza(com.google.android.gms.internal.zzaf.zzj r9, long r10, boolean r12) {
        /*
            r8 = this;
            r6 = 43200000(0x2932e00, double:2.1343636E-316)
            monitor-enter(r8)
            if (r12 == 0) goto Lc
            boolean r0 = r8.zzaKT     // Catch: java.lang.Throwable -> L6a
            if (r0 == 0) goto Lc
        La:
            monitor-exit(r8)
            return
        Lc:
            boolean r0 = r8.isReady()     // Catch: java.lang.Throwable -> L6a
            if (r0 == 0) goto L16
            com.google.android.gms.tagmanager.zzo r0 = r8.zzaKS     // Catch: java.lang.Throwable -> L6a
            if (r0 != 0) goto L16
        L16:
            r8.zzaKU = r9     // Catch: java.lang.Throwable -> L6a
            r8.zzaKD = r10     // Catch: java.lang.Throwable -> L6a
            r0 = 0
            r2 = 43200000(0x2932e00, double:2.1343636E-316)
            long r4 = r8.zzaKD     // Catch: java.lang.Throwable -> L6a
            long r4 = r4 + r6
            com.google.android.gms.internal.zzlb r6 = r8.zzpw     // Catch: java.lang.Throwable -> L6a
            long r6 = r6.currentTimeMillis()     // Catch: java.lang.Throwable -> L6a
            long r4 = r4 - r6
            long r2 = java.lang.Math.min(r2, r4)     // Catch: java.lang.Throwable -> L6a
            long r0 = java.lang.Math.max(r0, r2)     // Catch: java.lang.Throwable -> L6a
            r8.zzR(r0)     // Catch: java.lang.Throwable -> L6a
            com.google.android.gms.tagmanager.Container r0 = new com.google.android.gms.tagmanager.Container     // Catch: java.lang.Throwable -> L6a
            android.content.Context r1 = r8.mContext     // Catch: java.lang.Throwable -> L6a
            com.google.android.gms.tagmanager.TagManager r2 = r8.zzaKK     // Catch: java.lang.Throwable -> L6a
            com.google.android.gms.tagmanager.DataLayer r2 = r2.getDataLayer()     // Catch: java.lang.Throwable -> L6a
            java.lang.String r3 = r8.zzaKy     // Catch: java.lang.Throwable -> L6a
            r4 = r10
            r6 = r9
            r0.<init>(r1, r2, r3, r4, r6)     // Catch: java.lang.Throwable -> L6a
            com.google.android.gms.tagmanager.zzo r1 = r8.zzaKS     // Catch: java.lang.Throwable -> L6a
            if (r1 != 0) goto L6d
            com.google.android.gms.tagmanager.zzo r1 = new com.google.android.gms.tagmanager.zzo     // Catch: java.lang.Throwable -> L6a
            com.google.android.gms.tagmanager.TagManager r2 = r8.zzaKK     // Catch: java.lang.Throwable -> L6a
            android.os.Looper r3 = r8.zzWt     // Catch: java.lang.Throwable -> L6a
            com.google.android.gms.tagmanager.zzp$zzd r4 = r8.zzaKN     // Catch: java.lang.Throwable -> L6a
            r1.<init>(r2, r3, r0, r4)     // Catch: java.lang.Throwable -> L6a
            r8.zzaKS = r1     // Catch: java.lang.Throwable -> L6a
        L56:
            boolean r1 = r8.isReady()     // Catch: java.lang.Throwable -> L6a
            if (r1 != 0) goto La
            com.google.android.gms.tagmanager.zzp$zza r1 = r8.zzaKX     // Catch: java.lang.Throwable -> L6a
            boolean r0 = r1.zzb(r0)     // Catch: java.lang.Throwable -> L6a
            if (r0 == 0) goto La
            com.google.android.gms.tagmanager.zzo r0 = r8.zzaKS     // Catch: java.lang.Throwable -> L6a
            r8.setResult(r0)     // Catch: java.lang.Throwable -> L6a
            goto La
        L6a:
            r0 = move-exception
            monitor-exit(r8)
            throw r0
        L6d:
            com.google.android.gms.tagmanager.zzo r1 = r8.zzaKS     // Catch: java.lang.Throwable -> L6a
            r1.zza(r0)     // Catch: java.lang.Throwable -> L6a
            goto L56
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.tagmanager.zzp.zza(com.google.android.gms.internal.zzaf$zzj, long, boolean):void");
    }

    private void zzam(final boolean z) {
        this.zzaKQ.zza(new zzb());
        this.zzaKW.zza(new zzc());
        zzqf.zzc zziR = this.zzaKQ.zziR(this.zzaKP);
        if (zziR != null) {
            this.zzaKS = new zzo(this.zzaKK, this.zzWt, new Container(this.mContext, this.zzaKK.getDataLayer(), this.zzaKy, 0L, zziR), this.zzaKN);
        }
        this.zzaKX = new zza() { // from class: com.google.android.gms.tagmanager.zzp.3
            @Override // com.google.android.gms.tagmanager.zzp.zza
            public boolean zzb(Container container) {
                return z ? container.getLastRefreshTime() + 43200000 >= zzp.this.zzpw.currentTimeMillis() : !container.isDefault();
            }
        };
        if (zzyu()) {
            this.zzaKW.zzf(0L, "");
        } else {
            this.zzaKQ.zzyw();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean zzyu() {
        zzcb zzzf = zzcb.zzzf();
        return (zzzf.zzzg() == zzcb.zza.CONTAINER || zzzf.zzzg() == zzcb.zza.CONTAINER_DEBUG) && this.zzaKy.equals(zzzf.getContainerId());
    }

    public void load(final String resourceIdParameterName) {
        this.zzaKR.zza(this.zzaKy, this.zzaKP != -1 ? Integer.valueOf(this.zzaKP) : null, resourceIdParameterName, new zzqa.zza() { // from class: com.google.android.gms.tagmanager.zzp.1
            @Override // com.google.android.gms.internal.zzqa.zza
            public void zza(zzqe zzqeVar) {
                if (zzqeVar.getStatus() != Status.zzXP) {
                    zzbg.zzaz("Load request failed for the container " + zzp.this.zzaKy);
                    zzp.this.setResult(zzp.this.createFailedResult(Status.zzXR));
                    return;
                }
                zzqf.zzc zzAk = zzqeVar.zzAg().zzAk();
                if (zzAk == null) {
                    zzbg.zzaz("Response doesn't have the requested container");
                    zzp.this.setResult(zzp.this.createFailedResult(new Status(8, "Response doesn't have the requested container", null)));
                    return;
                }
                long zzAl = zzqeVar.zzAg().zzAl();
                zzp.this.zzaKS = new zzo(zzp.this.zzaKK, zzp.this.zzWt, new Container(zzp.this.mContext, zzp.this.zzaKK.getDataLayer(), zzp.this.zzaKy, zzAl, zzAk), new zzo.zza() { // from class: com.google.android.gms.tagmanager.zzp.1.1
                    @Override // com.google.android.gms.tagmanager.zzo.zza
                    public void zzej(String str) {
                        zzp.this.zzej(str);
                    }

                    @Override // com.google.android.gms.tagmanager.zzo.zza
                    public String zzyo() {
                        return zzp.this.zzyo();
                    }

                    @Override // com.google.android.gms.tagmanager.zzo.zza
                    public void zzyq() {
                        if (zzp.this.zzaKO.zzkb()) {
                            zzp.this.load(resourceIdParameterName);
                        }
                    }
                });
                zzp.this.setResult(zzp.this.zzaKS);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // com.google.android.gms.common.api.AbstractPendingResult
    /* renamed from: zzaU */
    public ContainerHolder createFailedResult(Status status) {
        if (this.zzaKS != null) {
            return this.zzaKS;
        }
        if (status == Status.zzXS) {
            zzbg.zzaz("timer expired: setting result to failure");
        }
        return new zzo(status);
    }

    synchronized void zzej(String str) {
        this.zzaKV = str;
        if (this.zzaKW != null) {
            this.zzaKW.zzem(str);
        }
    }

    synchronized String zzyo() {
        return this.zzaKV;
    }

    public void zzyr() {
        zzqf.zzc zziR = this.zzaKQ.zziR(this.zzaKP);
        if (zziR != null) {
            setResult(new zzo(this.zzaKK, this.zzWt, new Container(this.mContext, this.zzaKK.getDataLayer(), this.zzaKy, 0L, zziR), new zzo.zza() { // from class: com.google.android.gms.tagmanager.zzp.2
                @Override // com.google.android.gms.tagmanager.zzo.zza
                public void zzej(String str) {
                    zzp.this.zzej(str);
                }

                @Override // com.google.android.gms.tagmanager.zzo.zza
                public String zzyo() {
                    return zzp.this.zzyo();
                }

                @Override // com.google.android.gms.tagmanager.zzo.zza
                public void zzyq() {
                    zzbg.zzaC("Refresh ignored: container loaded as default only.");
                }
            }));
        } else {
            zzbg.zzaz("Default was requested, but no default container was found");
            setResult(createFailedResult(new Status(10, "Default was requested, but no default container was found", null)));
        }
        this.zzaKW = null;
        this.zzaKQ = null;
    }

    public void zzys() {
        zzam(false);
    }

    public void zzyt() {
        zzam(true);
    }
}
