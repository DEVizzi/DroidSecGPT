package com.google.android.gms.tagmanager;

import android.content.Context;
import com.google.android.gms.internal.zzaf;
import com.google.android.gms.tagmanager.zzp;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes.dex */
public class zzcm implements zzp.zze {
    private boolean mClosed;
    private final Context mContext;
    private String zzaKV;
    private final String zzaKy;
    private zzbf<zzaf.zzj> zzaMU;
    private zzs zzaMV;
    private final ScheduledExecutorService zzaMX;
    private final zza zzaMY;
    private ScheduledFuture<?> zzaMZ;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public interface zza {
        zzcl zza(zzs zzsVar);
    }

    /* loaded from: classes.dex */
    interface zzb {
        ScheduledExecutorService zzzm();
    }

    public zzcm(Context context, String str, zzs zzsVar) {
        this(context, str, zzsVar, null, null);
    }

    zzcm(Context context, String str, zzs zzsVar, zzb zzbVar, zza zzaVar) {
        this.zzaMV = zzsVar;
        this.mContext = context;
        this.zzaKy = str;
        this.zzaMX = (zzbVar == null ? new zzb() { // from class: com.google.android.gms.tagmanager.zzcm.1
            @Override // com.google.android.gms.tagmanager.zzcm.zzb
            public ScheduledExecutorService zzzm() {
                return Executors.newSingleThreadScheduledExecutor();
            }
        } : zzbVar).zzzm();
        if (zzaVar == null) {
            this.zzaMY = new zza() { // from class: com.google.android.gms.tagmanager.zzcm.2
                @Override // com.google.android.gms.tagmanager.zzcm.zza
                public zzcl zza(zzs zzsVar2) {
                    return new zzcl(zzcm.this.mContext, zzcm.this.zzaKy, zzsVar2);
                }
            };
        } else {
            this.zzaMY = zzaVar;
        }
    }

    private zzcl zzeC(String str) {
        zzcl zza2 = this.zzaMY.zza(this.zzaMV);
        zza2.zza(this.zzaMU);
        zza2.zzem(this.zzaKV);
        zza2.zzeB(str);
        return zza2;
    }

    private synchronized void zzzl() {
        if (this.mClosed) {
            throw new IllegalStateException("called method after closed");
        }
    }

    @Override // com.google.android.gms.common.api.Releasable
    public synchronized void release() {
        zzzl();
        if (this.zzaMZ != null) {
            this.zzaMZ.cancel(false);
        }
        this.zzaMX.shutdown();
        this.mClosed = true;
    }

    @Override // com.google.android.gms.tagmanager.zzp.zze
    public synchronized void zza(zzbf<zzaf.zzj> zzbfVar) {
        zzzl();
        this.zzaMU = zzbfVar;
    }

    @Override // com.google.android.gms.tagmanager.zzp.zze
    public synchronized void zzem(String str) {
        zzzl();
        this.zzaKV = str;
    }

    @Override // com.google.android.gms.tagmanager.zzp.zze
    public synchronized void zzf(long j, String str) {
        zzbg.zzaB("loadAfterDelay: containerId=" + this.zzaKy + " delay=" + j);
        zzzl();
        if (this.zzaMU == null) {
            throw new IllegalStateException("callback must be set before loadAfterDelay() is called.");
        }
        if (this.zzaMZ != null) {
            this.zzaMZ.cancel(false);
        }
        this.zzaMZ = this.zzaMX.schedule(zzeC(str), j, TimeUnit.MILLISECONDS);
    }
}
