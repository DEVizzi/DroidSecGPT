package com.google.android.gms.internal;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public final class zzdx {
    public final String zzxA;
    public final List<String> zzxB;
    public final List<String> zzxC;
    public final String zzxs;
    public final String zzxt;
    public final List<String> zzxu;
    public final String zzxv;
    public final String zzxw;
    public final List<String> zzxx;
    public final List<String> zzxy;
    public final String zzxz;

    public zzdx(JSONObject jSONObject) throws JSONException {
        this.zzxt = jSONObject.getString("id");
        JSONArray jSONArray = jSONObject.getJSONArray("adapters");
        ArrayList arrayList = new ArrayList(jSONArray.length());
        for (int i = 0; i < jSONArray.length(); i++) {
            arrayList.add(jSONArray.getString(i));
        }
        this.zzxu = Collections.unmodifiableList(arrayList);
        this.zzxv = jSONObject.optString("allocation_id", null);
        this.zzxx = com.google.android.gms.ads.internal.zzo.zzbG().zza(jSONObject, "clickurl");
        this.zzxy = com.google.android.gms.ads.internal.zzo.zzbG().zza(jSONObject, "imp_urls");
        this.zzxB = com.google.android.gms.ads.internal.zzo.zzbG().zza(jSONObject, "video_start_urls");
        this.zzxC = com.google.android.gms.ads.internal.zzo.zzbG().zza(jSONObject, "video_complete_urls");
        JSONObject optJSONObject = jSONObject.optJSONObject("ad");
        this.zzxs = optJSONObject != null ? optJSONObject.toString() : null;
        JSONObject optJSONObject2 = jSONObject.optJSONObject("data");
        this.zzxz = optJSONObject2 != null ? optJSONObject2.toString() : null;
        if (optJSONObject2 == null || optJSONObject2.isNull("equivalent_ad_network_id")) {
            this.zzxA = this.zzxt;
        } else {
            this.zzxA = optJSONObject2.optString("equivalent_ad_network_id", this.zzxt);
        }
        this.zzxw = optJSONObject2 != null ? optJSONObject2.optString("class_name") : null;
    }
}
