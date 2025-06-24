package com.google.android.gms.games.internal.events;

import android.os.Handler;
import android.os.Looper;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
/* loaded from: classes.dex */
public abstract class EventIncrementCache {
    private Handler zzasH;
    private boolean zzasI;
    private int zzasK;
    final Object zzasG = new Object();
    private HashMap<String, AtomicInteger> zzasJ = new HashMap<>();

    public EventIncrementCache(Looper looper, int flushIntervalMillis) {
        this.zzasH = new Handler(looper);
        this.zzasK = flushIntervalMillis;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzth() {
        synchronized (this.zzasG) {
            this.zzasI = false;
            flush();
        }
    }

    public void flush() {
        synchronized (this.zzasG) {
            for (Map.Entry<String, AtomicInteger> entry : this.zzasJ.entrySet()) {
                zzs(entry.getKey(), entry.getValue().get());
            }
            this.zzasJ.clear();
        }
    }

    protected abstract void zzs(String str, int i);

    public void zzw(String str, int i) {
        synchronized (this.zzasG) {
            if (!this.zzasI) {
                this.zzasI = true;
                this.zzasH.postDelayed(new Runnable() { // from class: com.google.android.gms.games.internal.events.EventIncrementCache.1
                    @Override // java.lang.Runnable
                    public void run() {
                        EventIncrementCache.this.zzth();
                    }
                }, this.zzasK);
            }
            AtomicInteger atomicInteger = this.zzasJ.get(str);
            if (atomicInteger == null) {
                atomicInteger = new AtomicInteger();
                this.zzasJ.put(str, atomicInteger);
            }
            atomicInteger.addAndGet(i);
        }
    }
}
