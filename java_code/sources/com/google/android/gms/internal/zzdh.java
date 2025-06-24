package com.google.android.gms.internal;

import android.content.Context;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.plus.PlusShare;
import java.io.BufferedOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzdh implements zzdg {
    private final Context mContext;
    private final VersionInfoParcel zzoM;

    /* JADX INFO: Access modifiers changed from: package-private */
    @zzgd
    /* loaded from: classes.dex */
    public static class zza {
        private final String mValue;
        private final String zztw;

        public zza(String str, String str2) {
            this.zztw = str;
            this.mValue = str2;
        }

        public String getKey() {
            return this.zztw;
        }

        public String getValue() {
            return this.mValue;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @zzgd
    /* loaded from: classes.dex */
    public static class zzb {
        private final String zzwl;
        private final URL zzwm;
        private final ArrayList<zza> zzwn;
        private final String zzwo;

        public zzb(String str, URL url, ArrayList<zza> arrayList, String str2) {
            this.zzwl = str;
            this.zzwm = url;
            if (arrayList == null) {
                this.zzwn = new ArrayList<>();
            } else {
                this.zzwn = arrayList;
            }
            this.zzwo = str2;
        }

        public String zzdJ() {
            return this.zzwl;
        }

        public URL zzdK() {
            return this.zzwm;
        }

        public ArrayList<zza> zzdL() {
            return this.zzwn;
        }

        public String zzdM() {
            return this.zzwo;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @zzgd
    /* loaded from: classes.dex */
    public class zzc {
        private final zzd zzwp;
        private final boolean zzwq;
        private final String zzwr;

        public zzc(boolean z, zzd zzdVar, String str) {
            this.zzwq = z;
            this.zzwp = zzdVar;
            this.zzwr = str;
        }

        public String getReason() {
            return this.zzwr;
        }

        public boolean isSuccess() {
            return this.zzwq;
        }

        public zzd zzdN() {
            return this.zzwp;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    @zzgd
    /* loaded from: classes.dex */
    public static class zzd {
        private final String zzvj;
        private final String zzwl;
        private final int zzws;
        private final List<zza> zzwt;

        public zzd(String str, int i, List<zza> list, String str2) {
            this.zzwl = str;
            this.zzws = i;
            if (list == null) {
                this.zzwt = new ArrayList();
            } else {
                this.zzwt = list;
            }
            this.zzvj = str2;
        }

        public String getBody() {
            return this.zzvj;
        }

        public int getResponseCode() {
            return this.zzws;
        }

        public String zzdJ() {
            return this.zzwl;
        }

        public Iterable<zza> zzdO() {
            return this.zzwt;
        }
    }

    public zzdh(Context context, VersionInfoParcel versionInfoParcel) {
        this.mContext = context;
        this.zzoM = versionInfoParcel;
    }

    public JSONObject zzT(String str) {
        try {
            JSONObject jSONObject = new JSONObject(str);
            JSONObject jSONObject2 = new JSONObject();
            String str2 = "";
            try {
                str2 = jSONObject.optString("http_request_id");
                zzc zza2 = zza(zzb(jSONObject));
                if (zza2.isSuccess()) {
                    jSONObject2.put("response", zza(zza2.zzdN()));
                    jSONObject2.put("success", true);
                } else {
                    jSONObject2.put("response", new JSONObject().put("http_request_id", str2));
                    jSONObject2.put("success", false);
                    jSONObject2.put("reason", zza2.getReason());
                }
                return jSONObject2;
            } catch (Exception e) {
                try {
                    jSONObject2.put("response", new JSONObject().put("http_request_id", str2));
                    jSONObject2.put("success", false);
                    jSONObject2.put("reason", e.toString());
                    return jSONObject2;
                } catch (JSONException e2) {
                    return jSONObject2;
                }
            }
        } catch (JSONException e3) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("The request is not a valid JSON.");
            try {
                return new JSONObject().put("success", false);
            } catch (JSONException e4) {
                return new JSONObject();
            }
        }
    }

    protected zzc zza(zzb zzbVar) {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) zzbVar.zzdK().openConnection();
            com.google.android.gms.ads.internal.zzo.zzbv().zza(this.mContext, this.zzoM.zzGG, false, httpURLConnection);
            Iterator<zza> it = zzbVar.zzdL().iterator();
            while (it.hasNext()) {
                zza next = it.next();
                httpURLConnection.addRequestProperty(next.getKey(), next.getValue());
            }
            if (!TextUtils.isEmpty(zzbVar.zzdM())) {
                httpURLConnection.setDoOutput(true);
                byte[] bytes = zzbVar.zzdM().getBytes();
                httpURLConnection.setFixedLengthStreamingMode(bytes.length);
                BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(httpURLConnection.getOutputStream());
                bufferedOutputStream.write(bytes);
                bufferedOutputStream.close();
            }
            ArrayList arrayList = new ArrayList();
            if (httpURLConnection.getHeaderFields() != null) {
                for (Map.Entry<String, List<String>> entry : httpURLConnection.getHeaderFields().entrySet()) {
                    for (String str : entry.getValue()) {
                        arrayList.add(new zza(entry.getKey(), str));
                    }
                }
            }
            return new zzc(true, new zzd(zzbVar.zzdJ(), httpURLConnection.getResponseCode(), arrayList, com.google.android.gms.ads.internal.zzo.zzbv().zza(new InputStreamReader(httpURLConnection.getInputStream()))), null);
        } catch (Exception e) {
            return new zzc(false, null, e.toString());
        }
    }

    protected JSONObject zza(zzd zzdVar) {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("http_request_id", zzdVar.zzdJ());
            if (zzdVar.getBody() != null) {
                jSONObject.put("body", zzdVar.getBody());
            }
            JSONArray jSONArray = new JSONArray();
            for (zza zzaVar : zzdVar.zzdO()) {
                jSONArray.put(new JSONObject().put("key", zzaVar.getKey()).put("value", zzaVar.getValue()));
            }
            jSONObject.put("headers", jSONArray);
            jSONObject.put("response_code", zzdVar.getResponseCode());
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Error constructing JSON for http response.", e);
        }
        return jSONObject;
    }

    @Override // com.google.android.gms.internal.zzdg
    public void zza(final zzid zzidVar, final Map<String, String> map) {
        zzhk.zza(new Runnable() { // from class: com.google.android.gms.internal.zzdh.1
            @Override // java.lang.Runnable
            public void run() {
                com.google.android.gms.ads.internal.util.client.zzb.zzay("Received Http request.");
                final JSONObject zzT = zzdh.this.zzT((String) map.get("http_request"));
                if (zzT == null) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzaz("Response should not be null.");
                } else {
                    zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzdh.1.1
                        @Override // java.lang.Runnable
                        public void run() {
                            zzidVar.zzb("fetchHttpRequestCompleted", zzT);
                            com.google.android.gms.ads.internal.util.client.zzb.zzay("Dispatched http response.");
                        }
                    });
                }
            }
        });
    }

    protected zzb zzb(JSONObject jSONObject) {
        URL url;
        String optString = jSONObject.optString("http_request_id");
        String optString2 = jSONObject.optString(PlusShare.KEY_CALL_TO_ACTION_URL);
        String optString3 = jSONObject.optString("post_body", null);
        try {
            url = new URL(optString2);
        } catch (MalformedURLException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzb("Error constructing http request.", e);
            url = null;
        }
        ArrayList arrayList = new ArrayList();
        JSONArray optJSONArray = jSONObject.optJSONArray("headers");
        if (optJSONArray == null) {
            optJSONArray = new JSONArray();
        }
        for (int i = 0; i < optJSONArray.length(); i++) {
            JSONObject optJSONObject = optJSONArray.optJSONObject(i);
            if (optJSONObject != null) {
                arrayList.add(new zza(optJSONObject.optString("key"), optJSONObject.optString("value")));
            }
        }
        return new zzb(optString, url, arrayList, optString3);
    }
}
