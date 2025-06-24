package com.google.android.gms.internal;

import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public final class zzax {
    private final String zzqo;
    private final JSONObject zzqp;
    private final String zzqq;
    private final String zzqr;
    private final boolean zzqs;

    public zzax(String str, VersionInfoParcel versionInfoParcel, String str2, JSONObject jSONObject, boolean z) {
        this.zzqr = versionInfoParcel.zzGG;
        this.zzqp = jSONObject;
        this.zzqq = str;
        this.zzqo = str2;
        this.zzqs = z;
    }

    public String zzbQ() {
        return this.zzqo;
    }

    public String zzbR() {
        return this.zzqr;
    }

    public JSONObject zzbS() {
        return this.zzqp;
    }

    public String zzbT() {
        return this.zzqq;
    }

    public boolean zzbU() {
        return this.zzqs;
    }
}
