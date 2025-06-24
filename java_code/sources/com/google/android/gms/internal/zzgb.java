package com.google.android.gms.internal;

import com.google.android.gms.internal.zzfy;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzgb implements zzfy.zza<com.google.android.gms.ads.internal.formats.zzf> {
    private final boolean zzBY;

    public zzgb(boolean z) {
        this.zzBY = z;
    }

    private void zza(zzfy zzfyVar, JSONObject jSONObject, zzkw<String, Future<com.google.android.gms.ads.internal.formats.zzc>> zzkwVar) throws JSONException {
        zzkwVar.put(jSONObject.getString("name"), zzfyVar.zza(jSONObject, "image_value", this.zzBY));
    }

    private void zza(JSONObject jSONObject, zzkw<String, String> zzkwVar) throws JSONException {
        zzkwVar.put(jSONObject.getString("name"), jSONObject.getString("string_value"));
    }

    private <K, V> zzkw<K, V> zzc(zzkw<K, Future<V>> zzkwVar) throws InterruptedException, ExecutionException {
        zzkw<K, V> zzkwVar2 = new zzkw<>();
        int i = 0;
        while (true) {
            int i2 = i;
            if (i2 >= zzkwVar.size()) {
                return zzkwVar2;
            }
            zzkwVar2.put(zzkwVar.keyAt(i2), zzkwVar.valueAt(i2).get());
            i = i2 + 1;
        }
    }

    @Override // com.google.android.gms.internal.zzfy.zza
    /* renamed from: zzd */
    public com.google.android.gms.ads.internal.formats.zzf zza(zzfy zzfyVar, JSONObject jSONObject) throws JSONException, InterruptedException, ExecutionException {
        zzkw<String, Future<com.google.android.gms.ads.internal.formats.zzc>> zzkwVar = new zzkw<>();
        zzkw<String, String> zzkwVar2 = new zzkw<>();
        zzhv<com.google.android.gms.ads.internal.formats.zza> zze = zzfyVar.zze(jSONObject);
        JSONArray jSONArray = jSONObject.getJSONArray("custom_assets");
        for (int i = 0; i < jSONArray.length(); i++) {
            JSONObject jSONObject2 = jSONArray.getJSONObject(i);
            String string = jSONObject2.getString("type");
            if ("string".equals(string)) {
                zza(jSONObject2, zzkwVar2);
            } else if ("image".equals(string)) {
                zza(zzfyVar, jSONObject2, zzkwVar);
            } else {
                com.google.android.gms.ads.internal.util.client.zzb.zzaC("Unknown custom asset type: " + string);
            }
        }
        return new com.google.android.gms.ads.internal.formats.zzf(jSONObject.getString("custom_template_id"), zzc(zzkwVar), zzkwVar2, zze.get());
    }
}
