package com.google.android.gms.internal;

import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import java.util.Collections;
import java.util.List;
/* loaded from: classes.dex */
public class zzbt implements zzbu {
    @Override // com.google.android.gms.internal.zzbu
    public List<String> zza(AdRequestInfoParcel adRequestInfoParcel) {
        return adRequestInfoParcel.zzCF == null ? Collections.emptyList() : adRequestInfoParcel.zzCF;
    }
}
