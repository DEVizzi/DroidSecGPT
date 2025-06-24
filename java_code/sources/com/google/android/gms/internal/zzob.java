package com.google.android.gms.internal;

import android.text.TextUtils;
import com.google.android.gms.plus.PlusShare;
import java.util.HashMap;
/* loaded from: classes.dex */
public final class zzob extends zznq<zzob> {
    private String mCategory;
    private String zzaEH;
    private long zzaoL;
    private String zzuO;

    public String getAction() {
        return this.zzuO;
    }

    public String getLabel() {
        return this.zzaEH;
    }

    public long getValue() {
        return this.zzaoL;
    }

    public String toString() {
        HashMap hashMap = new HashMap();
        hashMap.put("category", this.mCategory);
        hashMap.put("action", this.zzuO);
        hashMap.put(PlusShare.KEY_CALL_TO_ACTION_LABEL, this.zzaEH);
        hashMap.put("value", Long.valueOf(this.zzaoL));
        return zzy(hashMap);
    }

    public void zzM(long j) {
        this.zzaoL = j;
    }

    @Override // com.google.android.gms.internal.zznq
    public void zza(zzob zzobVar) {
        if (!TextUtils.isEmpty(this.mCategory)) {
            zzobVar.zzdG(this.mCategory);
        }
        if (!TextUtils.isEmpty(this.zzuO)) {
            zzobVar.zzdH(this.zzuO);
        }
        if (!TextUtils.isEmpty(this.zzaEH)) {
            zzobVar.zzdI(this.zzaEH);
        }
        if (this.zzaoL != 0) {
            zzobVar.zzM(this.zzaoL);
        }
    }

    public void zzdG(String str) {
        this.mCategory = str;
    }

    public void zzdH(String str) {
        this.zzuO = str;
    }

    public void zzdI(String str) {
        this.zzaEH = str;
    }

    public String zzwy() {
        return this.mCategory;
    }
}
