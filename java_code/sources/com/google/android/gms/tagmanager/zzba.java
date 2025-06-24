package com.google.android.gms.tagmanager;

import android.util.LruCache;
import com.google.android.gms.tagmanager.zzm;
/* loaded from: classes.dex */
class zzba<K, V> implements zzl<K, V> {
    private LruCache<K, V> zzaMe;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzba(int i, final zzm.zza<K, V> zzaVar) {
        this.zzaMe = new LruCache<K, V>(i) { // from class: com.google.android.gms.tagmanager.zzba.1
            @Override // android.util.LruCache
            protected int sizeOf(K key, V value) {
                return zzaVar.sizeOf(key, value);
            }
        };
    }

    @Override // com.google.android.gms.tagmanager.zzl
    public V get(K key) {
        return this.zzaMe.get(key);
    }

    @Override // com.google.android.gms.tagmanager.zzl
    public void zzf(K k, V v) {
        this.zzaMe.put(k, v);
    }
}
