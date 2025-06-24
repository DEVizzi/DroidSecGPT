package com.google.android.gms.internal;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzdl implements zzdg {
    final HashMap<String, zzhs<JSONObject>> zzwv = new HashMap<>();

    public Future<JSONObject> zzU(String str) {
        zzhs<JSONObject> zzhsVar = new zzhs<>();
        this.zzwv.put(str, zzhsVar);
        return zzhsVar;
    }

    public void zzV(String str) {
        zzhs<JSONObject> zzhsVar = this.zzwv.get(str);
        if (zzhsVar == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Could not find the ad request for the corresponding ad response.");
            return;
        }
        if (!zzhsVar.isDone()) {
            zzhsVar.cancel(true);
        }
        this.zzwv.remove(str);
    }

    @Override // com.google.android.gms.internal.zzdg
    public void zza(zzid zzidVar, Map<String, String> map) {
        zze(map.get("request_id"), map.get("fetched_ad"));
    }

    public void zze(String str, String str2) {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("Received ad from the cache.");
        zzhs<JSONObject> zzhsVar = this.zzwv.get(str);
        if (zzhsVar == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Could not find the ad request for the corresponding ad response.");
            return;
        }
        try {
            zzhsVar.zzf(new JSONObject(str2));
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Failed constructing JSON object from value passed from javascript", e);
            zzhsVar.zzf(null);
        } finally {
            this.zzwv.remove(str);
        }
    }
}
