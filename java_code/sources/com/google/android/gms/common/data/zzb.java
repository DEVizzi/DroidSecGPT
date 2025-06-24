package com.google.android.gms.common.data;

import com.google.android.gms.common.internal.zzu;
import java.util.Iterator;
import java.util.NoSuchElementException;
/* loaded from: classes.dex */
public class zzb<T> implements Iterator<T> {
    protected final DataBuffer<T> zzYp;
    protected int zzYq = -1;

    public zzb(DataBuffer<T> dataBuffer) {
        this.zzYp = (DataBuffer) zzu.zzu(dataBuffer);
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.zzYq < this.zzYp.getCount() + (-1);
    }

    @Override // java.util.Iterator
    public T next() {
        if (hasNext()) {
            DataBuffer<T> dataBuffer = this.zzYp;
            int i = this.zzYq + 1;
            this.zzYq = i;
            return dataBuffer.get(i);
        }
        throw new NoSuchElementException("Cannot advance the iterator beyond " + this.zzYq);
    }

    @Override // java.util.Iterator
    public void remove() {
        throw new UnsupportedOperationException("Cannot remove elements from a DataBufferIterator");
    }
}
