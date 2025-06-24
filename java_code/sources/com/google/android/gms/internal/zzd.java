package com.google.android.gms.internal;
/* loaded from: classes.dex */
public class zzd implements zzo {
    private int zzo;
    private int zzp;
    private final int zzq;
    private final float zzr;

    public zzd() {
        this(2500, 1, 1.0f);
    }

    public zzd(int i, int i2, float f) {
        this.zzo = i;
        this.zzq = i2;
        this.zzr = f;
    }

    @Override // com.google.android.gms.internal.zzo
    public void zza(zzr zzrVar) throws zzr {
        this.zzp++;
        this.zzo = (int) (this.zzo + (this.zzo * this.zzr));
        if (!zzf()) {
            throw zzrVar;
        }
    }

    @Override // com.google.android.gms.internal.zzo
    public int zzd() {
        return this.zzo;
    }

    @Override // com.google.android.gms.internal.zzo
    public int zze() {
        return this.zzp;
    }

    protected boolean zzf() {
        return this.zzp <= this.zzq;
    }
}
