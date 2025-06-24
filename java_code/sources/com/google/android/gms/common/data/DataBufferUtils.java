package com.google.android.gms.common.data;

import android.os.Bundle;
import java.util.ArrayList;
/* loaded from: classes.dex */
public final class DataBufferUtils {
    private DataBufferUtils() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static <T, E extends Freezable<T>> ArrayList<T> freezeAndClose(DataBuffer<E> buffer) {
        ArrayList<T> arrayList = (ArrayList<T>) new ArrayList(buffer.getCount());
        try {
            for (E e : buffer) {
                arrayList.add(e.freeze());
            }
            return arrayList;
        } finally {
            buffer.close();
        }
    }

    public static boolean hasData(DataBuffer<?> buffer) {
        return buffer != null && buffer.getCount() > 0;
    }

    public static boolean hasNextPage(DataBuffer<?> buffer) {
        Bundle zznb = buffer.zznb();
        return (zznb == null || zznb.getString("next_page_token") == null) ? false : true;
    }

    public static boolean hasPrevPage(DataBuffer<?> buffer) {
        Bundle zznb = buffer.zznb();
        return (zznb == null || zznb.getString("prev_page_token") == null) ? false : true;
    }
}
