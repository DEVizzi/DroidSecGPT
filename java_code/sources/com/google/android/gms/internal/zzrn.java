package com.google.android.gms.internal;

import java.io.IOException;
/* loaded from: classes.dex */
public abstract class zzrn {
    protected volatile int zzaWf = -1;

    public static final <T extends zzrn> T zza(T t, byte[] bArr) throws zzrm {
        return (T) zzb(t, bArr, 0, bArr.length);
    }

    public static final void zza(zzrn zzrnVar, byte[] bArr, int i, int i2) {
        try {
            zzrg zzb = zzrg.zzb(bArr, i, i2);
            zzrnVar.zza(zzb);
            zzb.zzBH();
        } catch (IOException e) {
            throw new RuntimeException("Serializing to a byte array threw an IOException (should never happen).", e);
        }
    }

    public static final <T extends zzrn> T zzb(T t, byte[] bArr, int i, int i2) throws zzrm {
        try {
            zzrf zza = zzrf.zza(bArr, i, i2);
            t.zzb(zza);
            zza.zzkz(0);
            return t;
        } catch (zzrm e) {
            throw e;
        } catch (IOException e2) {
            throw new RuntimeException("Reading from a byte array threw an IOException (should never happen).");
        }
    }

    public static final byte[] zzf(zzrn zzrnVar) {
        byte[] bArr = new byte[zzrnVar.zzBV()];
        zza(zzrnVar, bArr, 0, bArr.length);
        return bArr;
    }

    public String toString() {
        return zzro.zzg(this);
    }

    protected int zzB() {
        return 0;
    }

    @Override // 
    /* renamed from: zzBK */
    public zzrn clone() throws CloneNotSupportedException {
        return (zzrn) super.clone();
    }

    public int zzBU() {
        if (this.zzaWf < 0) {
            zzBV();
        }
        return this.zzaWf;
    }

    public int zzBV() {
        int zzB = zzB();
        this.zzaWf = zzB;
        return zzB;
    }

    public void zza(zzrg zzrgVar) throws IOException {
    }

    public abstract zzrn zzb(zzrf zzrfVar) throws IOException;
}
