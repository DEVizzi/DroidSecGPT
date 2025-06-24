package com.google.android.gms.internal;

import android.util.Base64;
/* loaded from: classes.dex */
class zzah implements zzap {
    @Override // com.google.android.gms.internal.zzap
    public String zza(byte[] bArr, boolean z) {
        return Base64.encodeToString(bArr, z ? 11 : 2);
    }

    @Override // com.google.android.gms.internal.zzap
    public byte[] zza(String str, boolean z) throws IllegalArgumentException {
        return Base64.decode(str, z ? 11 : 2);
    }
}
