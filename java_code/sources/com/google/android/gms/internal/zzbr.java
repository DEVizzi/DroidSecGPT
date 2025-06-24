package com.google.android.gms.internal;

import android.text.TextUtils;
@zzgd
/* loaded from: classes.dex */
public final class zzbr {
    private String zztu;
    private int zztv;

    public zzbr() {
        this(zzbz.zztD.zzcY(), -1);
    }

    public zzbr(String str) {
        this(str, -1);
    }

    public zzbr(String str, int i) {
        this.zztv = -1;
        this.zztu = TextUtils.isEmpty(str) ? zzbz.zztD.zzcY() : str;
        this.zztv = i;
    }

    public String zzcW() {
        return this.zztu;
    }

    public int zzcX() {
        return this.zztv;
    }
}
