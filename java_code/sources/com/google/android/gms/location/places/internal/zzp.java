package com.google.android.gms.location.places.internal;
/* loaded from: classes.dex */
public class zzp implements com.google.android.gms.location.places.zzg {
    private int mIndex;
    private final String zzaAW;
    private final CharSequence zzaAX;
    private final int zzyZ;
    private final int zzza;

    public zzp(String str, int i, int i2, CharSequence charSequence, int i3) {
        this.zzaAW = str;
        this.zzyZ = i;
        this.zzza = i2;
        this.zzaAX = charSequence;
        this.mIndex = i3;
    }

    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        if (other instanceof zzp) {
            zzp zzpVar = (zzp) other;
            return zzpVar.zzyZ == this.zzyZ && zzpVar.zzza == this.zzza && com.google.android.gms.common.internal.zzt.equal(zzpVar.zzaAW, this.zzaAW) && com.google.android.gms.common.internal.zzt.equal(zzpVar.zzaAX, this.zzaAX);
        }
        return false;
    }

    public int hashCode() {
        return com.google.android.gms.common.internal.zzt.hashCode(Integer.valueOf(this.zzyZ), Integer.valueOf(this.zzza), this.zzaAW, this.zzaAX);
    }

    @Override // com.google.android.gms.common.data.Freezable
    public boolean isDataValid() {
        return true;
    }

    @Override // com.google.android.gms.common.data.Freezable
    /* renamed from: zzuZ */
    public com.google.android.gms.location.places.zzg freeze() {
        return this;
    }
}
