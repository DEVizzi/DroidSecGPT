package com.google.android.gms.internal;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
@zzgd
/* loaded from: classes.dex */
public class zzbi {
    private int zzrt;
    private final Object zzqt = new Object();
    private List<zzbh> zzru = new LinkedList();

    public boolean zza(zzbh zzbhVar) {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzru.contains(zzbhVar);
        }
        return z;
    }

    public boolean zzb(zzbh zzbhVar) {
        boolean z;
        synchronized (this.zzqt) {
            Iterator<zzbh> it = this.zzru.iterator();
            while (true) {
                if (!it.hasNext()) {
                    z = false;
                    break;
                }
                zzbh next = it.next();
                if (zzbhVar != next && next.zzci().equals(zzbhVar.zzci())) {
                    it.remove();
                    z = true;
                    break;
                }
            }
        }
        return z;
    }

    public void zzc(zzbh zzbhVar) {
        synchronized (this.zzqt) {
            if (this.zzru.size() >= 10) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Queue is full, current size = " + this.zzru.size());
                this.zzru.remove(0);
            }
            int i = this.zzrt;
            this.zzrt = i + 1;
            zzbhVar.zzg(i);
            this.zzru.add(zzbhVar);
        }
    }

    public zzbh zzco() {
        int i;
        zzbh zzbhVar;
        zzbh zzbhVar2 = null;
        synchronized (this.zzqt) {
            if (this.zzru.size() == 0) {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Queue empty");
                return null;
            } else if (this.zzru.size() < 2) {
                zzbh zzbhVar3 = this.zzru.get(0);
                zzbhVar3.zzcj();
                return zzbhVar3;
            } else {
                int i2 = Integer.MIN_VALUE;
                for (zzbh zzbhVar4 : this.zzru) {
                    int score = zzbhVar4.getScore();
                    if (score > i2) {
                        zzbhVar = zzbhVar4;
                        i = score;
                    } else {
                        i = i2;
                        zzbhVar = zzbhVar2;
                    }
                    i2 = i;
                    zzbhVar2 = zzbhVar;
                }
                this.zzru.remove(zzbhVar2);
                return zzbhVar2;
            }
        }
    }
}
