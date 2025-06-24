package com.google.android.gms.internal;

import android.os.Handler;
import android.os.Looper;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
/* loaded from: classes.dex */
public class zzl {
    private AtomicInteger zzY;
    private final Map<String, Queue<zzk<?>>> zzZ;
    private final Set<zzk<?>> zzaa;
    private final PriorityBlockingQueue<zzk<?>> zzab;
    private final PriorityBlockingQueue<zzk<?>> zzac;
    private zzg[] zzad;
    private zzc zzae;
    private List<zza> zzaf;
    private final zzb zzj;
    private final zzn zzk;
    private final zzf zzz;

    /* loaded from: classes.dex */
    public interface zza<T> {
        void zzg(zzk<T> zzkVar);
    }

    public zzl(zzb zzbVar, zzf zzfVar) {
        this(zzbVar, zzfVar, 4);
    }

    public zzl(zzb zzbVar, zzf zzfVar, int i) {
        this(zzbVar, zzfVar, i, new zze(new Handler(Looper.getMainLooper())));
    }

    public zzl(zzb zzbVar, zzf zzfVar, int i, zzn zznVar) {
        this.zzY = new AtomicInteger();
        this.zzZ = new HashMap();
        this.zzaa = new HashSet();
        this.zzab = new PriorityBlockingQueue<>();
        this.zzac = new PriorityBlockingQueue<>();
        this.zzaf = new ArrayList();
        this.zzj = zzbVar;
        this.zzz = zzfVar;
        this.zzad = new zzg[i];
        this.zzk = zznVar;
    }

    public int getSequenceNumber() {
        return this.zzY.incrementAndGet();
    }

    public void start() {
        stop();
        this.zzae = new zzc(this.zzab, this.zzac, this.zzj, this.zzk);
        this.zzae.start();
        for (int i = 0; i < this.zzad.length; i++) {
            zzg zzgVar = new zzg(this.zzac, this.zzz, this.zzj, this.zzk);
            this.zzad[i] = zzgVar;
            zzgVar.start();
        }
    }

    public void stop() {
        if (this.zzae != null) {
            this.zzae.quit();
        }
        for (int i = 0; i < this.zzad.length; i++) {
            if (this.zzad[i] != null) {
                this.zzad[i].quit();
            }
        }
    }

    public <T> zzk<T> zze(zzk<T> zzkVar) {
        zzkVar.zza(this);
        synchronized (this.zzaa) {
            this.zzaa.add(zzkVar);
        }
        zzkVar.zza(getSequenceNumber());
        zzkVar.zzc("add-to-queue");
        if (zzkVar.zzr()) {
            synchronized (this.zzZ) {
                String zzh = zzkVar.zzh();
                if (this.zzZ.containsKey(zzh)) {
                    Queue<zzk<?>> queue = this.zzZ.get(zzh);
                    if (queue == null) {
                        queue = new LinkedList<>();
                    }
                    queue.add(zzkVar);
                    this.zzZ.put(zzh, queue);
                    if (zzs.DEBUG) {
                        zzs.zza("Request for cacheKey=%s is in flight, putting on hold.", zzh);
                    }
                } else {
                    this.zzZ.put(zzh, null);
                    this.zzab.add(zzkVar);
                }
            }
        } else {
            this.zzac.add(zzkVar);
        }
        return zzkVar;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public <T> void zzf(zzk<T> zzkVar) {
        synchronized (this.zzaa) {
            this.zzaa.remove(zzkVar);
        }
        synchronized (this.zzaf) {
            for (zza zzaVar : this.zzaf) {
                zzaVar.zzg(zzkVar);
            }
        }
        if (zzkVar.zzr()) {
            synchronized (this.zzZ) {
                String zzh = zzkVar.zzh();
                Queue<zzk<?>> remove = this.zzZ.remove(zzh);
                if (remove != null) {
                    if (zzs.DEBUG) {
                        zzs.zza("Releasing %d waiting requests for cacheKey=%s.", Integer.valueOf(remove.size()), zzh);
                    }
                    this.zzab.addAll(remove);
                }
            }
        }
    }
}
