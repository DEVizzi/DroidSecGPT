package com.google.android.gms.internal;
/* loaded from: classes.dex */
public class zzpy {
    private final String zzaKy;
    private final String zzaMW;
    private final Integer zzaPb;
    private final String zzaPc;
    private final boolean zzaPd;

    public zzpy(String str, Integer num, String str2, boolean z) {
        this(str, num, str2, z, "");
    }

    public zzpy(String str, Integer num, String str2, boolean z, String str3) {
        com.google.android.gms.common.internal.zzu.zzu(str);
        com.google.android.gms.common.internal.zzu.zzu(str3);
        this.zzaKy = str;
        this.zzaPb = num;
        this.zzaPc = str2;
        this.zzaPd = z;
        this.zzaMW = str3;
    }

    public String getContainerId() {
        return this.zzaKy;
    }

    public String zzAa() {
        return this.zzaPc;
    }

    public String zzAb() {
        return this.zzaPc != null ? this.zzaPc + "_" + this.zzaKy : this.zzaKy;
    }

    public boolean zzAc() {
        return this.zzaPd;
    }

    public String zzAd() {
        return this.zzaMW;
    }

    public Integer zzzZ() {
        return this.zzaPb;
    }
}
