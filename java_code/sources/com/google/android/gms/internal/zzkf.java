package com.google.android.gms.internal;

import android.os.Binder;
/* loaded from: classes.dex */
public abstract class zzkf<T> {
    private T zzLS = null;
    protected final String zztw;
    protected final T zztx;
    private static final Object zzoW = new Object();
    private static zza zzYj = null;
    private static int zzYk = 0;
    private static String zzYl = "com.google.android.providers.gsf.permission.READ_GSERVICES";

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: classes.dex */
    public interface zza {
        Long getLong(String str, Long l);

        String getString(String str, String str2);

        Boolean zzb(String str, Boolean bool);

        Float zzb(String str, Float f);

        Integer zzb(String str, Integer num);
    }

    protected zzkf(String str, T t) {
        this.zztw = str;
        this.zztx = t;
    }

    public static boolean isInitialized() {
        return zzYj != null;
    }

    public static zzkf<Float> zza(String str, Float f) {
        return new zzkf<Float>(str, f) { // from class: com.google.android.gms.internal.zzkf.4
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzkf
            /* renamed from: zzbT */
            public Float zzbP(String str2) {
                return zzkf.zzYj.zzb(this.zztw, (Float) this.zztx);
            }
        };
    }

    public static zzkf<Integer> zza(String str, Integer num) {
        return new zzkf<Integer>(str, num) { // from class: com.google.android.gms.internal.zzkf.3
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzkf
            /* renamed from: zzbS */
            public Integer zzbP(String str2) {
                return zzkf.zzYj.zzb(this.zztw, (Integer) this.zztx);
            }
        };
    }

    public static zzkf<Long> zza(String str, Long l) {
        return new zzkf<Long>(str, l) { // from class: com.google.android.gms.internal.zzkf.2
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzkf
            /* renamed from: zzbR */
            public Long zzbP(String str2) {
                return zzkf.zzYj.getLong(this.zztw, (Long) this.zztx);
            }
        };
    }

    public static zzkf<Boolean> zzg(String str, boolean z) {
        return new zzkf<Boolean>(str, Boolean.valueOf(z)) { // from class: com.google.android.gms.internal.zzkf.1
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzkf
            /* renamed from: zzbQ */
            public Boolean zzbP(String str2) {
                return zzkf.zzYj.zzb(this.zztw, (Boolean) this.zztx);
            }
        };
    }

    public static int zzmY() {
        return zzYk;
    }

    public static zzkf<String> zzs(String str, String str2) {
        return new zzkf<String>(str, str2) { // from class: com.google.android.gms.internal.zzkf.5
            /* JADX INFO: Access modifiers changed from: protected */
            @Override // com.google.android.gms.internal.zzkf
            /* renamed from: zzbU */
            public String zzbP(String str3) {
                return zzkf.zzYj.getString(this.zztw, (String) this.zztx);
            }
        };
    }

    public final T get() {
        return this.zzLS != null ? this.zzLS : zzbP(this.zztw);
    }

    protected abstract T zzbP(String str);

    public final T zzmZ() {
        long clearCallingIdentity = Binder.clearCallingIdentity();
        try {
            return get();
        } finally {
            Binder.restoreCallingIdentity(clearCallingIdentity);
        }
    }
}
