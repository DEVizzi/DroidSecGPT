package com.google.android.gms.internal;

import java.util.concurrent.TimeUnit;
@zzgd
/* loaded from: classes.dex */
public class zzht<T> implements zzhv<T> {
    private final T zzGK;
    private final zzhw zzGM = new zzhw();

    public zzht(T t) {
        this.zzGK = t;
        this.zzGM.zzgy();
    }

    @Override // java.util.concurrent.Future
    public boolean cancel(boolean mayInterruptIfRunning) {
        return false;
    }

    @Override // java.util.concurrent.Future
    public T get() {
        return this.zzGK;
    }

    @Override // java.util.concurrent.Future
    public T get(long timeout, TimeUnit unit) {
        return this.zzGK;
    }

    @Override // java.util.concurrent.Future
    public boolean isCancelled() {
        return false;
    }

    @Override // java.util.concurrent.Future
    public boolean isDone() {
        return true;
    }

    @Override // com.google.android.gms.internal.zzhv
    public void zzb(Runnable runnable) {
        this.zzGM.zzb(runnable);
    }
}
