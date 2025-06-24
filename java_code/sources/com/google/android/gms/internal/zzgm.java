package com.google.android.gms.internal;

import com.google.android.gms.ads.internal.reward.client.zza;
/* loaded from: classes.dex */
public class zzgm extends zza.AbstractBinderC0018zza {
    private final int zzEL;
    private final String zzEl;

    public zzgm(String str, int i) {
        this.zzEl = str;
        this.zzEL = i;
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zza
    public int getAmount() {
        return this.zzEL;
    }

    @Override // com.google.android.gms.ads.internal.reward.client.zza
    public String getType() {
        return this.zzEl;
    }
}
