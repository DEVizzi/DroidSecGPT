package com.google.android.gms.internal;

import com.google.android.gms.internal.zzb;
/* loaded from: classes.dex */
public class zzm<T> {
    public final T result;
    public final zzb.zza zzag;
    public final zzr zzah;
    public boolean zzai;

    /* loaded from: classes.dex */
    public interface zza {
        void zze(zzr zzrVar);
    }

    /* loaded from: classes.dex */
    public interface zzb<T> {
        void zzb(T t);
    }

    private zzm(zzr zzrVar) {
        this.zzai = false;
        this.result = null;
        this.zzag = null;
        this.zzah = zzrVar;
    }

    private zzm(T t, zzb.zza zzaVar) {
        this.zzai = false;
        this.result = t;
        this.zzag = zzaVar;
        this.zzah = null;
    }

    public static <T> zzm<T> zza(T t, zzb.zza zzaVar) {
        return new zzm<>(t, zzaVar);
    }

    public static <T> zzm<T> zzd(zzr zzrVar) {
        return new zzm<>(zzrVar);
    }

    public boolean isSuccess() {
        return this.zzah == null;
    }
}
