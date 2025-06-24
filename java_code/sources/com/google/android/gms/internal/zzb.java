package com.google.android.gms.internal;

import java.util.Collections;
import java.util.Map;
/* loaded from: classes.dex */
public interface zzb {

    /* loaded from: classes.dex */
    public static class zza {
        public byte[] data;
        public String zzb;
        public long zzc;
        public long zzd;
        public long zze;
        public long zzf;
        public Map<String, String> zzg = Collections.emptyMap();

        public boolean zzb() {
            return this.zze < System.currentTimeMillis();
        }

        public boolean zzc() {
            return this.zzf < System.currentTimeMillis();
        }
    }

    zza zza(String str);

    void zza();

    void zza(String str, zza zzaVar);
}
