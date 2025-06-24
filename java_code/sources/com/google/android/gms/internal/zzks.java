package com.google.android.gms.internal;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
/* loaded from: classes.dex */
public class zzks<K, V> extends zzkw<K, V> implements Map<K, V> {
    zzkv<K, V> zzabl;

    private zzkv<K, V> zzog() {
        if (this.zzabl == null) {
            this.zzabl = new zzkv<K, V>() { // from class: com.google.android.gms.internal.zzks.1
                @Override // com.google.android.gms.internal.zzkv
                protected void colClear() {
                    zzks.this.clear();
                }

                @Override // com.google.android.gms.internal.zzkv
                protected Object colGetEntry(int index, int offset) {
                    return zzks.this.mArray[(index << 1) + offset];
                }

                @Override // com.google.android.gms.internal.zzkv
                protected Map<K, V> colGetMap() {
                    return zzks.this;
                }

                @Override // com.google.android.gms.internal.zzkv
                protected int colGetSize() {
                    return zzks.this.mSize;
                }

                @Override // com.google.android.gms.internal.zzkv
                protected int colIndexOfKey(Object key) {
                    return key == null ? zzks.this.indexOfNull() : zzks.this.indexOf(key, key.hashCode());
                }

                @Override // com.google.android.gms.internal.zzkv
                protected int colIndexOfValue(Object value) {
                    return zzks.this.indexOfValue(value);
                }

                @Override // com.google.android.gms.internal.zzkv
                protected void colPut(K key, V value) {
                    zzks.this.put(key, value);
                }

                @Override // com.google.android.gms.internal.zzkv
                protected void colRemoveAt(int index) {
                    zzks.this.removeAt(index);
                }

                @Override // com.google.android.gms.internal.zzkv
                protected V colSetValue(int index, V value) {
                    return zzks.this.setValueAt(index, value);
                }
            };
        }
        return this.zzabl;
    }

    @Override // java.util.Map
    public Set<Map.Entry<K, V>> entrySet() {
        return zzog().getEntrySet();
    }

    @Override // java.util.Map
    public Set<K> keySet() {
        return zzog().getKeySet();
    }

    @Override // java.util.Map
    public void putAll(Map<? extends K, ? extends V> map) {
        ensureCapacity(this.mSize + map.size());
        for (Map.Entry<? extends K, ? extends V> entry : map.entrySet()) {
            put(entry.getKey(), entry.getValue());
        }
    }

    @Override // java.util.Map
    public Collection<V> values() {
        return zzog().getValues();
    }
}
