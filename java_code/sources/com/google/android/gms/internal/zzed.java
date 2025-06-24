package com.google.android.gms.internal;

import android.content.Context;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzed {
    public List<String> zza(JSONObject jSONObject, String str) throws JSONException {
        JSONArray optJSONArray = jSONObject.optJSONArray(str);
        if (optJSONArray != null) {
            ArrayList arrayList = new ArrayList(optJSONArray.length());
            for (int i = 0; i < optJSONArray.length(); i++) {
                arrayList.add(optJSONArray.getString(i));
            }
            return Collections.unmodifiableList(arrayList);
        }
        return null;
    }

    public void zza(Context context, String str, zzha zzhaVar, String str2, boolean z, List<String> list) {
        if (list == null || list.isEmpty()) {
            return;
        }
        String str3 = z ? "1" : "0";
        for (String str4 : list) {
            String replaceAll = str4.replaceAll("@gw_adlocid@", str2).replaceAll("@gw_adnetrefresh@", str3).replaceAll("@gw_qdata@", zzhaVar.zzFm.zzxI).replaceAll("@gw_sdkver@", str).replaceAll("@gw_sessid@", com.google.android.gms.ads.internal.zzo.zzby().getSessionId()).replaceAll("@gw_seqnum@", zzhaVar.zzCp);
            if (zzhaVar.zzxZ != null) {
                replaceAll = replaceAll.replaceAll("@gw_adnetid@", zzhaVar.zzxZ.zzxt).replaceAll("@gw_allocid@", zzhaVar.zzxZ.zzxv);
            }
            new zzhp(context, str, replaceAll).zzgi();
        }
    }
}
