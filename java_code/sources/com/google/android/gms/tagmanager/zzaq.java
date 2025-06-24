package com.google.android.gms.tagmanager;

import android.text.TextUtils;
/* loaded from: classes.dex */
class zzaq {
    private final long zzMb;
    private final long zzaLL;
    private final long zzaLM;
    private String zzaLN;

    /* JADX INFO: Access modifiers changed from: package-private */
    public zzaq(long j, long j2, long j3) {
        this.zzaLL = j;
        this.zzMb = j2;
        this.zzaLM = j3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void zzev(String str) {
        if (str == null || TextUtils.isEmpty(str.trim())) {
            return;
        }
        this.zzaLN = str;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long zzyO() {
        return this.zzaLL;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public long zzyP() {
        return this.zzaLM;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String zzyQ() {
        return this.zzaLN;
    }
}
