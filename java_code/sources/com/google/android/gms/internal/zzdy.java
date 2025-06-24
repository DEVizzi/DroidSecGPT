package com.google.android.gms.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public final class zzdy {
    public final List<zzdx> zzxD;
    public final long zzxE;
    public final List<String> zzxF;
    public final List<String> zzxG;
    public final List<String> zzxH;
    public final String zzxI;
    public final long zzxJ;
    public final String zzxK;
    public final int zzxL;
    public int zzxM;
    public int zzxN;

    public zzdy(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject(str);
        if (com.google.android.gms.ads.internal.util.client.zzb.zzL(2)) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaB("Mediation Response JSON: " + jSONObject.toString(2));
        }
        JSONArray jSONArray = jSONObject.getJSONArray("ad_networks");
        ArrayList arrayList = new ArrayList(jSONArray.length());
        int i = -1;
        for (int i2 = 0; i2 < jSONArray.length(); i2++) {
            zzdx zzdxVar = new zzdx(jSONArray.getJSONObject(i2));
            arrayList.add(zzdxVar);
            if (i < 0 && zza(zzdxVar)) {
                i = i2;
            }
        }
        this.zzxM = i;
        this.zzxN = jSONArray.length();
        this.zzxD = Collections.unmodifiableList(arrayList);
        this.zzxI = jSONObject.getString("qdata");
        JSONObject optJSONObject = jSONObject.optJSONObject("settings");
        if (optJSONObject == null) {
            this.zzxE = -1L;
            this.zzxF = null;
            this.zzxG = null;
            this.zzxH = null;
            this.zzxJ = -1L;
            this.zzxK = null;
            this.zzxL = 0;
            return;
        }
        this.zzxE = optJSONObject.optLong("ad_network_timeout_millis", -1L);
        this.zzxF = com.google.android.gms.ads.internal.zzo.zzbG().zza(optJSONObject, "click_urls");
        this.zzxG = com.google.android.gms.ads.internal.zzo.zzbG().zza(optJSONObject, "imp_urls");
        this.zzxH = com.google.android.gms.ads.internal.zzo.zzbG().zza(optJSONObject, "nofill_urls");
        long optLong = optJSONObject.optLong("refresh", -1L);
        this.zzxJ = optLong > 0 ? optLong * 1000 : -1L;
        JSONArray optJSONArray = optJSONObject.optJSONArray("rewards");
        if (optJSONArray == null || optJSONArray.length() == 0) {
            this.zzxK = null;
            this.zzxL = 0;
            return;
        }
        this.zzxK = optJSONArray.getJSONObject(0).optString("rb_type");
        this.zzxL = optJSONArray.getJSONObject(0).optInt("rb_amount");
    }

    private boolean zza(zzdx zzdxVar) {
        for (String str : zzdxVar.zzxu) {
            if (str.equals("com.google.ads.mediation.admob.AdMobAdapter")) {
                return true;
            }
        }
        return false;
    }
}
