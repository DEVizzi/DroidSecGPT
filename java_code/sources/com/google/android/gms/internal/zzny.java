package com.google.android.gms.internal;

import android.text.TextUtils;
import java.util.HashMap;
/* loaded from: classes.dex */
public final class zzny extends zznq<zzny> {
    private String mName;
    private String zzKI;
    private String zzaEA;
    private String zzaEB;
    private String zzaEC;
    private String zzaED;
    private String zzaEy;
    private String zzaEz;
    private String zzazL;
    private String zzuU;

    public String getContent() {
        return this.zzuU;
    }

    public String getId() {
        return this.zzKI;
    }

    public String getName() {
        return this.mName;
    }

    public String getSource() {
        return this.zzazL;
    }

    public void setName(String name) {
        this.mName = name;
    }

    public String toString() {
        HashMap hashMap = new HashMap();
        hashMap.put("name", this.mName);
        hashMap.put("source", this.zzazL);
        hashMap.put("medium", this.zzaEy);
        hashMap.put("keyword", this.zzaEz);
        hashMap.put("content", this.zzuU);
        hashMap.put("id", this.zzKI);
        hashMap.put("adNetworkId", this.zzaEA);
        hashMap.put("gclid", this.zzaEB);
        hashMap.put("dclid", this.zzaEC);
        hashMap.put("aclid", this.zzaED);
        return zzy(hashMap);
    }

    @Override // com.google.android.gms.internal.zznq
    public void zza(zzny zznyVar) {
        if (!TextUtils.isEmpty(this.mName)) {
            zznyVar.setName(this.mName);
        }
        if (!TextUtils.isEmpty(this.zzazL)) {
            zznyVar.zzdx(this.zzazL);
        }
        if (!TextUtils.isEmpty(this.zzaEy)) {
            zznyVar.zzdy(this.zzaEy);
        }
        if (!TextUtils.isEmpty(this.zzaEz)) {
            zznyVar.zzdz(this.zzaEz);
        }
        if (!TextUtils.isEmpty(this.zzuU)) {
            zznyVar.zzdA(this.zzuU);
        }
        if (!TextUtils.isEmpty(this.zzKI)) {
            zznyVar.zzdB(this.zzKI);
        }
        if (!TextUtils.isEmpty(this.zzaEA)) {
            zznyVar.zzdC(this.zzaEA);
        }
        if (!TextUtils.isEmpty(this.zzaEB)) {
            zznyVar.zzdD(this.zzaEB);
        }
        if (!TextUtils.isEmpty(this.zzaEC)) {
            zznyVar.zzdE(this.zzaEC);
        }
        if (TextUtils.isEmpty(this.zzaED)) {
            return;
        }
        zznyVar.zzdF(this.zzaED);
    }

    public void zzdA(String str) {
        this.zzuU = str;
    }

    public void zzdB(String str) {
        this.zzKI = str;
    }

    public void zzdC(String str) {
        this.zzaEA = str;
    }

    public void zzdD(String str) {
        this.zzaEB = str;
    }

    public void zzdE(String str) {
        this.zzaEC = str;
    }

    public void zzdF(String str) {
        this.zzaED = str;
    }

    public void zzdx(String str) {
        this.zzazL = str;
    }

    public void zzdy(String str) {
        this.zzaEy = str;
    }

    public void zzdz(String str) {
        this.zzaEz = str;
    }

    public String zzwj() {
        return this.zzaEy;
    }

    public String zzwk() {
        return this.zzaEz;
    }

    public String zzwl() {
        return this.zzaEA;
    }

    public String zzwm() {
        return this.zzaEB;
    }

    public String zzwn() {
        return this.zzaEC;
    }

    public String zzwo() {
        return this.zzaED;
    }
}
