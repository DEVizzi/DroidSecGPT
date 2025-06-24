package com.google.android.gms.internal;

import java.io.IOException;
import java.util.Arrays;
/* loaded from: classes.dex */
final class zzrp {
    final int tag;
    final byte[] zzaWg;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzrp(int i, byte[] bArr) {
        this.tag = i;
        this.zzaWg = bArr;
    }

    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (o instanceof zzrp) {
            zzrp zzrpVar = (zzrp) o;
            return this.tag == zzrpVar.tag && Arrays.equals(this.zzaWg, zzrpVar.zzaWg);
        }
        return false;
    }

    public int hashCode() {
        return ((this.tag + 527) * 31) + Arrays.hashCode(this.zzaWg);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int zzB() {
        return 0 + zzrg.zzkO(this.tag) + this.zzaWg.length;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zza(zzrg zzrgVar) throws IOException {
        zzrgVar.zzkN(this.tag);
        zzrgVar.zzD(this.zzaWg);
    }
}
