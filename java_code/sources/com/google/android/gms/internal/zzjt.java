package com.google.android.gms.internal;

import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
public final class zzjt {
    private final String zzTO;
    private final int zzTP;
    private final String zzTQ;

    public zzjt(String str, int i, String str2) {
        this.zzTO = str;
        this.zzTP = i;
        this.zzTQ = str2;
    }

    public zzjt(JSONObject jSONObject) throws JSONException {
        this(jSONObject.optString("applicationName"), jSONObject.optInt("maxPlayers"), jSONObject.optString("version"));
    }

    public final int getMaxPlayers() {
        return this.zzTP;
    }

    public final String getVersion() {
        return this.zzTQ;
    }

    public final String zzlB() {
        return this.zzTO;
    }
}
