package com.google.android.gms.internal;

import android.text.TextUtils;
import java.util.HashMap;
/* loaded from: classes.dex */
public final class zzip extends zznq<zzip> {
    private String zzEO;
    private String zzJc;
    private String zzJd;
    private String zzJe;
    private boolean zzJf;
    private String zzJg;
    private boolean zzJh;
    private double zzJi;

    public String getClientId() {
        return this.zzJd;
    }

    public String getUserId() {
        return this.zzEO;
    }

    public void setClientId(String clientId) {
        this.zzJd = clientId;
    }

    public void setSampleRate(double percentage) {
        com.google.android.gms.common.internal.zzu.zzb(percentage >= 0.0d && percentage <= 100.0d, "Sample rate must be between 0% and 100%");
        this.zzJi = percentage;
    }

    public void setUserId(String userId) {
        this.zzEO = userId;
    }

    public String toString() {
        HashMap hashMap = new HashMap();
        hashMap.put("hitType", this.zzJc);
        hashMap.put("clientId", this.zzJd);
        hashMap.put("userId", this.zzEO);
        hashMap.put("androidAdId", this.zzJe);
        hashMap.put("AdTargetingEnabled", Boolean.valueOf(this.zzJf));
        hashMap.put("sessionControl", this.zzJg);
        hashMap.put("nonInteraction", Boolean.valueOf(this.zzJh));
        hashMap.put("sampleRate", Double.valueOf(this.zzJi));
        return zzy(hashMap);
    }

    public void zzE(boolean z) {
        this.zzJf = z;
    }

    public void zzF(boolean z) {
        this.zzJh = z;
    }

    @Override // com.google.android.gms.internal.zznq
    public void zza(zzip zzipVar) {
        if (!TextUtils.isEmpty(this.zzJc)) {
            zzipVar.zzaN(this.zzJc);
        }
        if (!TextUtils.isEmpty(this.zzJd)) {
            zzipVar.setClientId(this.zzJd);
        }
        if (!TextUtils.isEmpty(this.zzEO)) {
            zzipVar.setUserId(this.zzEO);
        }
        if (!TextUtils.isEmpty(this.zzJe)) {
            zzipVar.zzaO(this.zzJe);
        }
        if (this.zzJf) {
            zzipVar.zzE(true);
        }
        if (!TextUtils.isEmpty(this.zzJg)) {
            zzipVar.zzaP(this.zzJg);
        }
        if (this.zzJh) {
            zzipVar.zzF(this.zzJh);
        }
        if (this.zzJi != 0.0d) {
            zzipVar.setSampleRate(this.zzJi);
        }
    }

    public void zzaN(String str) {
        this.zzJc = str;
    }

    public void zzaO(String str) {
        this.zzJe = str;
    }

    public void zzaP(String str) {
        this.zzJg = str;
    }

    public boolean zzhA() {
        return this.zzJh;
    }

    public double zzhB() {
        return this.zzJi;
    }

    public String zzhw() {
        return this.zzJc;
    }

    public String zzhx() {
        return this.zzJe;
    }

    public boolean zzhy() {
        return this.zzJf;
    }

    public String zzhz() {
        return this.zzJg;
    }
}
