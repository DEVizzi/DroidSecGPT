package com.google.android.gms.internal;

import android.text.TextUtils;
import com.google.android.gms.plus.PlusShare;
import java.util.HashMap;
/* loaded from: classes.dex */
public final class zzoc extends zznq<zzoc> {
    public boolean zzaEI;
    public String zzakM;

    public String getDescription() {
        return this.zzakM;
    }

    public void setDescription(String description) {
        this.zzakM = description;
    }

    public String toString() {
        HashMap hashMap = new HashMap();
        hashMap.put(PlusShare.KEY_CONTENT_DEEP_LINK_METADATA_DESCRIPTION, this.zzakM);
        hashMap.put("fatal", Boolean.valueOf(this.zzaEI));
        return zzy(hashMap);
    }

    @Override // com.google.android.gms.internal.zznq
    public void zza(zzoc zzocVar) {
        if (!TextUtils.isEmpty(this.zzakM)) {
            zzocVar.setDescription(this.zzakM);
        }
        if (this.zzaEI) {
            zzocVar.zzag(this.zzaEI);
        }
    }

    public void zzag(boolean z) {
        this.zzaEI = z;
    }

    public boolean zzwz() {
        return this.zzaEI;
    }
}
