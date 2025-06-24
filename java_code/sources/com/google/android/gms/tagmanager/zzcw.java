package com.google.android.gms.tagmanager;

import com.google.android.gms.tagmanager.zzm;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
/* loaded from: classes.dex */
class zzcw<K, V> implements zzl<K, V> {
    private final Map<K, V> zzaNR = new HashMap();
    private final int zzaNS;
    private final zzm.zza<K, V> zzaNT;
    private int zzaNU;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzcw(int i, zzm.zza<K, V> zzaVar) {
        this.zzaNS = i;
        this.zzaNT = zzaVar;
    }

    @Override // com.google.android.gms.tagmanager.zzl
    public synchronized V get(K key) {
        return this.zzaNR.get(key);
    }

    @Override // com.google.android.gms.tagmanager.zzl
    public synchronized void zzf(K k, V v) {
        if (k == null || v == null) {
            throw new NullPointerException("key == null || value == null");
        }
        this.zzaNU += this.zzaNT.sizeOf(k, v);
        if (this.zzaNU > this.zzaNS) {
            Iterator<Map.Entry<K, V>> it = this.zzaNR.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<K, V> next = it.next();
                this.zzaNU -= this.zzaNT.sizeOf(next.getKey(), next.getValue());
                it.remove();
                if (this.zzaNU <= this.zzaNS) {
                    break;
                }
            }
        }
        this.zzaNR.put(k, v);
    }
}
