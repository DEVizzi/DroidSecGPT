package com.google.android.gms.internal;

import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
@zzgd
/* loaded from: classes.dex */
public class zzhs<T> implements zzhv<T> {
    private final Object zzqt = new Object();
    private T zzGK = null;
    private boolean zzGL = false;
    private boolean zzxo = false;
    private final zzhw zzGM = new zzhw();

    @Override // java.util.concurrent.Future
    public boolean cancel(boolean mayInterruptIfRunning) {
        boolean z = false;
        if (mayInterruptIfRunning) {
            synchronized (this.zzqt) {
                if (!this.zzGL) {
                    this.zzxo = true;
                    this.zzGL = true;
                    this.zzqt.notifyAll();
                    this.zzGM.zzgy();
                    z = true;
                }
            }
        }
        return z;
    }

    @Override // java.util.concurrent.Future
    public T get() {
        T t;
        synchronized (this.zzqt) {
            if (!this.zzGL) {
                try {
                    this.zzqt.wait();
                } catch (InterruptedException e) {
                }
            }
            if (this.zzxo) {
                throw new CancellationException("CallbackFuture was cancelled.");
            }
            t = this.zzGK;
        }
        return t;
    }

    @Override // java.util.concurrent.Future
    public T get(long timeout, TimeUnit unit) throws TimeoutException {
        T t;
        synchronized (this.zzqt) {
            if (!this.zzGL) {
                try {
                    long millis = unit.toMillis(timeout);
                    if (millis != 0) {
                        this.zzqt.wait(millis);
                    }
                } catch (InterruptedException e) {
                }
            }
            if (!this.zzGL) {
                throw new TimeoutException("CallbackFuture timed out.");
            }
            if (this.zzxo) {
                throw new CancellationException("CallbackFuture was cancelled.");
            }
            t = this.zzGK;
        }
        return t;
    }

    @Override // java.util.concurrent.Future
    public boolean isCancelled() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzxo;
        }
        return z;
    }

    @Override // java.util.concurrent.Future
    public boolean isDone() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzGL;
        }
        return z;
    }

    @Override // com.google.android.gms.internal.zzhv
    public void zzb(Runnable runnable) {
        this.zzGM.zzb(runnable);
    }

    public void zzf(T t) {
        synchronized (this.zzqt) {
            if (this.zzGL) {
                throw new IllegalStateException("Provided CallbackFuture with multiple values.");
            }
            this.zzGL = true;
            this.zzGK = t;
            this.zzqt.notifyAll();
            this.zzGM.zzgy();
        }
    }
}
