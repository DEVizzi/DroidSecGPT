package com.google.android.gms.internal;

import android.os.Bundle;
@zzgd
/* loaded from: classes.dex */
public class zzhf {
    private int zzFV;
    private int zzFW;
    private final String zzFv;
    private final zzhc zzpv;
    private final Object zzqt;

    zzhf(zzhc zzhcVar, String str) {
        this.zzqt = new Object();
        this.zzpv = zzhcVar;
        this.zzFv = str;
    }

    public zzhf(String str) {
        this(com.google.android.gms.ads.internal.zzo.zzby(), str);
    }

    public Bundle toBundle() {
        Bundle bundle;
        synchronized (this.zzqt) {
            bundle = new Bundle();
            bundle.putInt("pmnli", this.zzFV);
            bundle.putInt("pmnll", this.zzFW);
        }
        return bundle;
    }

    public void zzf(int i, int i2) {
        synchronized (this.zzqt) {
            this.zzFV = i;
            this.zzFW = i2;
            this.zzpv.zza(this.zzFv, this);
        }
    }
}
