package com.google.android.gms.internal;

import com.google.android.gms.common.api.Result;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.internal.zzqf;
/* loaded from: classes.dex */
public class zzqe implements Result {
    private final zza zzaPo;

    /* loaded from: classes.dex */
    public static class zza {
        private final Status zzOt;
        private final EnumC0156zza zzaPp;
        private final byte[] zzaPq;
        private final long zzaPr;
        private final zzpy zzaPs;
        private final zzqf.zzc zzaPt;

        /* renamed from: com.google.android.gms.internal.zzqe$zza$zza  reason: collision with other inner class name */
        /* loaded from: classes.dex */
        public enum EnumC0156zza {
            NETWORK,
            DISK,
            DEFAULT
        }

        public zza(Status status, zzpy zzpyVar, EnumC0156zza enumC0156zza) {
            this(status, zzpyVar, null, null, enumC0156zza, 0L);
        }

        public zza(Status status, zzpy zzpyVar, byte[] bArr, zzqf.zzc zzcVar, EnumC0156zza enumC0156zza, long j) {
            this.zzOt = status;
            this.zzaPs = zzpyVar;
            this.zzaPq = bArr;
            this.zzaPt = zzcVar;
            this.zzaPp = enumC0156zza;
            this.zzaPr = j;
        }

        public Status getStatus() {
            return this.zzOt;
        }

        public EnumC0156zza zzAh() {
            return this.zzaPp;
        }

        public byte[] zzAi() {
            return this.zzaPq;
        }

        public zzpy zzAj() {
            return this.zzaPs;
        }

        public zzqf.zzc zzAk() {
            return this.zzaPt;
        }

        public long zzAl() {
            return this.zzaPr;
        }
    }

    public zzqe(zza zzaVar) {
        this.zzaPo = zzaVar;
    }

    @Override // com.google.android.gms.common.api.Result
    public Status getStatus() {
        return this.zzaPo.getStatus();
    }

    public zza zzAg() {
        return this.zzaPo;
    }
}
