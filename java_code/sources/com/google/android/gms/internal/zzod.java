package com.google.android.gms.internal;

import android.support.v7.internal.widget.ActivityChooserView;
import android.text.TextUtils;
import android.util.Log;
import java.util.HashMap;
import java.util.UUID;
/* loaded from: classes.dex */
public final class zzod extends zznq<zzod> {
    private String zzaEJ;
    private int zzaEK;
    private int zzaEL;
    private String zzaEM;
    private String zzaEN;
    private boolean zzaEO;
    private boolean zzaEP;
    private boolean zzaEQ;

    public zzod() {
        this(false);
    }

    public zzod(boolean z) {
        this(z, zzwA());
    }

    public zzod(boolean z, int i) {
        com.google.android.gms.common.internal.zzu.zzbw(i);
        this.zzaEK = i;
        this.zzaEP = z;
    }

    static int zzwA() {
        UUID randomUUID = UUID.randomUUID();
        int leastSignificantBits = (int) (randomUUID.getLeastSignificantBits() & 2147483647L);
        if (leastSignificantBits != 0) {
            return leastSignificantBits;
        }
        int mostSignificantBits = (int) (randomUUID.getMostSignificantBits() & 2147483647L);
        if (mostSignificantBits == 0) {
            Log.e("GAv4", "UUID.randomUUID() returned 0.");
            return ActivityChooserView.ActivityChooserViewAdapter.MAX_ACTIVITY_COUNT_UNLIMITED;
        }
        return mostSignificantBits;
    }

    private void zzwH() {
        if (this.zzaEQ) {
            throw new IllegalStateException("ScreenViewInfo is immutable");
        }
    }

    public boolean isMutable() {
        return !this.zzaEQ;
    }

    public void setScreenName(String screenName) {
        zzwH();
        this.zzaEJ = screenName;
    }

    public String toString() {
        HashMap hashMap = new HashMap();
        hashMap.put("screenName", this.zzaEJ);
        hashMap.put("interstitial", Boolean.valueOf(this.zzaEO));
        hashMap.put("automatic", Boolean.valueOf(this.zzaEP));
        hashMap.put("screenId", Integer.valueOf(this.zzaEK));
        hashMap.put("referrerScreenId", Integer.valueOf(this.zzaEL));
        hashMap.put("referrerScreenName", this.zzaEM);
        hashMap.put("referrerUri", this.zzaEN);
        return zzy(hashMap);
    }

    public void zzah(boolean z) {
        zzwH();
        this.zzaEP = z;
    }

    public void zzai(boolean z) {
        zzwH();
        this.zzaEO = z;
    }

    public int zzbn() {
        return this.zzaEK;
    }

    @Override // com.google.android.gms.internal.zznq
    /* renamed from: zzc */
    public void zza(zzod zzodVar) {
        if (!TextUtils.isEmpty(this.zzaEJ)) {
            zzodVar.setScreenName(this.zzaEJ);
        }
        if (this.zzaEK != 0) {
            zzodVar.zzhK(this.zzaEK);
        }
        if (this.zzaEL != 0) {
            zzodVar.zzhL(this.zzaEL);
        }
        if (!TextUtils.isEmpty(this.zzaEM)) {
            zzodVar.zzdJ(this.zzaEM);
        }
        if (!TextUtils.isEmpty(this.zzaEN)) {
            zzodVar.zzdK(this.zzaEN);
        }
        if (this.zzaEO) {
            zzodVar.zzai(this.zzaEO);
        }
        if (this.zzaEP) {
            zzodVar.zzah(this.zzaEP);
        }
    }

    public void zzdJ(String str) {
        zzwH();
        this.zzaEM = str;
    }

    public void zzdK(String str) {
        zzwH();
        if (TextUtils.isEmpty(str)) {
            this.zzaEN = null;
        } else {
            this.zzaEN = str;
        }
    }

    public void zzhK(int i) {
        zzwH();
        this.zzaEK = i;
    }

    public void zzhL(int i) {
        zzwH();
        this.zzaEL = i;
    }

    public String zzwB() {
        return this.zzaEJ;
    }

    public int zzwC() {
        return this.zzaEL;
    }

    public String zzwD() {
        return this.zzaEM;
    }

    public String zzwE() {
        return this.zzaEN;
    }

    public void zzwF() {
        this.zzaEQ = true;
    }

    public boolean zzwG() {
        return this.zzaEO;
    }
}
