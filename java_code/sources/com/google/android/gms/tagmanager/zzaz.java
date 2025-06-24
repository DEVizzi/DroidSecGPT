package com.google.android.gms.tagmanager;

import com.google.android.gms.internal.zzag;
import com.google.android.gms.internal.zzqf;
import java.util.HashMap;
import java.util.Iterator;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
/* loaded from: classes.dex */
class zzaz {
    private static zzag.zza zzB(Object obj) throws JSONException {
        return zzdf.zzI(zzC(obj));
    }

    static Object zzC(Object obj) throws JSONException {
        if (obj instanceof JSONArray) {
            throw new RuntimeException("JSONArrays are not supported");
        }
        if (JSONObject.NULL.equals(obj)) {
            throw new RuntimeException("JSON nulls are not supported");
        }
        if (obj instanceof JSONObject) {
            JSONObject jSONObject = (JSONObject) obj;
            HashMap hashMap = new HashMap();
            Iterator<String> keys = jSONObject.keys();
            while (keys.hasNext()) {
                String next = keys.next();
                hashMap.put(next, zzC(jSONObject.get(next)));
            }
            return hashMap;
        }
        return obj;
    }

    public static zzqf.zzc zzey(String str) throws JSONException {
        zzag.zza zzB = zzB(new JSONObject(str));
        zzqf.zzd zzAp = zzqf.zzc.zzAp();
        for (int i = 0; i < zzB.zziT.length; i++) {
            zzAp.zzc(zzqf.zza.zzAm().zzb(com.google.android.gms.internal.zzae.INSTANCE_NAME.toString(), zzB.zziT[i]).zzb(com.google.android.gms.internal.zzae.FUNCTION.toString(), zzdf.zzeJ(zzn.zzyk())).zzb(zzn.zzyl(), zzB.zziU[i]).zzAo());
        }
        return zzAp.zzAs();
    }
}
