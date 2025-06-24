package com.google.android.gms.internal;

import java.io.IOException;
/* loaded from: classes.dex */
class zzas implements zzaq {
    private zzrg zznC;
    private byte[] zznD;
    private final int zznE;

    public zzas(int i) {
        this.zznE = i;
        reset();
    }

    @Override // com.google.android.gms.internal.zzaq
    public void reset() {
        this.zznD = new byte[this.zznE];
        this.zznC = zzrg.zzA(this.zznD);
    }

    @Override // com.google.android.gms.internal.zzaq
    public byte[] zzac() throws IOException {
        int zzBG = this.zznC.zzBG();
        if (zzBG < 0) {
            throw new IOException();
        }
        if (zzBG == 0) {
            return this.zznD;
        }
        byte[] bArr = new byte[this.zznD.length - zzBG];
        System.arraycopy(this.zznD, 0, bArr, 0, bArr.length);
        return bArr;
    }

    @Override // com.google.android.gms.internal.zzaq
    public void zzb(int i, long j) throws IOException {
        this.zznC.zzb(i, j);
    }

    @Override // com.google.android.gms.internal.zzaq
    public void zzb(int i, String str) throws IOException {
        this.zznC.zzb(i, str);
    }
}
