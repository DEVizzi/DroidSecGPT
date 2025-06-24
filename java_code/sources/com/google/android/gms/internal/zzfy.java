package com.google.android.gms.internal;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.RemoteException;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.formats.zzg;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzho;
import com.google.android.gms.internal.zzhu;
import com.google.android.gms.plus.PlusShare;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzfy implements Callable<zzha> {
    private static final long zzBF = TimeUnit.SECONDS.toMillis(60);
    private final Context mContext;
    private final zzho zzBG;
    private final com.google.android.gms.ads.internal.zzm zzBH;
    private final zzbc zzBI;
    private final zzha.zza zzBs;
    private final zzan zzvA;
    private final Object zzqt = new Object();
    private boolean zzBJ = false;
    private int zzBv = -2;
    private List<String> zzBK = null;

    /* loaded from: classes.dex */
    public interface zza<T extends zzg.zza> {
        T zza(zzfy zzfyVar, JSONObject jSONObject) throws JSONException, InterruptedException, ExecutionException;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public class zzb {
        public zzdg zzBX;

        zzb() {
        }
    }

    public zzfy(Context context, com.google.android.gms.ads.internal.zzm zzmVar, zzbc zzbcVar, zzho zzhoVar, zzan zzanVar, zzha.zza zzaVar) {
        this.mContext = context;
        this.zzBH = zzmVar;
        this.zzBG = zzhoVar;
        this.zzBI = zzbcVar;
        this.zzBs = zzaVar;
        this.zzvA = zzanVar;
    }

    private zzg.zza zza(zzbb zzbbVar, zza zzaVar, JSONObject jSONObject) throws ExecutionException, InterruptedException, JSONException {
        if (zzfr()) {
            return null;
        }
        String[] zzc = zzc(jSONObject.getJSONObject("tracking_urls_and_actions"), "impression_tracking_urls");
        this.zzBK = zzc == null ? null : Arrays.asList(zzc);
        zzg.zza zza2 = zzaVar.zza(this, jSONObject);
        if (zza2 == null) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("Failed to retrieve ad assets.");
            return null;
        }
        zza2.zza(new com.google.android.gms.ads.internal.formats.zzg(this.mContext, this.zzBH, zzbbVar, this.zzvA, jSONObject, zza2));
        return zza2;
    }

    private zzha zza(zzg.zza zzaVar) {
        int i;
        synchronized (this.zzqt) {
            i = this.zzBv;
            if (zzaVar == null && this.zzBv == -2) {
                i = 0;
            }
        }
        return new zzha(this.zzBs.zzFr.zzCm, null, this.zzBs.zzFs.zzxF, i, this.zzBs.zzFs.zzxG, this.zzBK, this.zzBs.zzFs.orientation, this.zzBs.zzFs.zzxJ, this.zzBs.zzFr.zzCp, false, null, null, null, null, null, 0L, this.zzBs.zzpN, this.zzBs.zzFs.zzCJ, this.zzBs.zzFo, this.zzBs.zzFp, this.zzBs.zzFs.zzCP, this.zzBs.zzFl, i != -2 ? null : zzaVar, this.zzBs.zzFr.zzCC);
    }

    private zzhv<com.google.android.gms.ads.internal.formats.zzc> zza(JSONObject jSONObject, final boolean z, boolean z2) throws JSONException {
        final String string = z ? jSONObject.getString(PlusShare.KEY_CALL_TO_ACTION_URL) : jSONObject.optString(PlusShare.KEY_CALL_TO_ACTION_URL);
        if (!TextUtils.isEmpty(string)) {
            return z2 ? new zzht(new com.google.android.gms.ads.internal.formats.zzc(null, Uri.parse(string))) : this.zzBG.zza(string, new zzho.zza<com.google.android.gms.ads.internal.formats.zzc>() { // from class: com.google.android.gms.internal.zzfy.5
                @Override // com.google.android.gms.internal.zzho.zza
                /* renamed from: zzfs */
                public com.google.android.gms.ads.internal.formats.zzc zzft() {
                    zzfy.this.zza(2, z);
                    return null;
                }

                @Override // com.google.android.gms.internal.zzho.zza
                /* renamed from: zzg */
                public com.google.android.gms.ads.internal.formats.zzc zzh(InputStream inputStream) {
                    byte[] bArr;
                    try {
                        bArr = zzlg.zzk(inputStream);
                    } catch (IOException e) {
                        bArr = null;
                    }
                    if (bArr == null) {
                        zzfy.this.zza(2, z);
                        return null;
                    }
                    Bitmap decodeByteArray = BitmapFactory.decodeByteArray(bArr, 0, bArr.length);
                    if (decodeByteArray == null) {
                        zzfy.this.zza(2, z);
                        return null;
                    }
                    return new com.google.android.gms.ads.internal.formats.zzc(new BitmapDrawable(Resources.getSystem(), decodeByteArray), Uri.parse(string));
                }
            });
        }
        zza(0, z);
        return new zzht(null);
    }

    private void zza(zzg.zza zzaVar, zzbb zzbbVar) {
        if (zzaVar instanceof com.google.android.gms.ads.internal.formats.zzf) {
            final com.google.android.gms.ads.internal.formats.zzf zzfVar = (com.google.android.gms.ads.internal.formats.zzf) zzaVar;
            zzb zzbVar = new zzb();
            zzdg zzdgVar = new zzdg() { // from class: com.google.android.gms.internal.zzfy.3
                @Override // com.google.android.gms.internal.zzdg
                public void zza(zzid zzidVar, Map<String, String> map) {
                    zzfy.this.zzb(zzfVar, map.get("asset"));
                }
            };
            zzbVar.zzBX = zzdgVar;
            zzbbVar.zza("/nativeAdCustomClick", zzdgVar);
        }
    }

    private Integer zzb(JSONObject jSONObject, String str) {
        try {
            JSONObject jSONObject2 = jSONObject.getJSONObject(str);
            return Integer.valueOf(Color.rgb(jSONObject2.getInt("r"), jSONObject2.getInt("g"), jSONObject2.getInt("b")));
        } catch (JSONException e) {
            return null;
        }
    }

    private JSONObject zzb(final zzbb zzbbVar) throws TimeoutException, JSONException {
        if (zzfr()) {
            return null;
        }
        final zzhs zzhsVar = new zzhs();
        final zzb zzbVar = new zzb();
        zzdg zzdgVar = new zzdg() { // from class: com.google.android.gms.internal.zzfy.1
            @Override // com.google.android.gms.internal.zzdg
            public void zza(zzid zzidVar, Map<String, String> map) {
                zzbbVar.zzb("/nativeAdPreProcess", zzbVar.zzBX);
                try {
                    String str = map.get("success");
                    if (!TextUtils.isEmpty(str)) {
                        zzhsVar.zzf(new JSONObject(str).getJSONArray("ads").getJSONObject(0));
                        return;
                    }
                } catch (JSONException e) {
                    com.google.android.gms.ads.internal.util.client.zzb.zzb("Malformed native JSON response.", e);
                }
                zzfy.this.zzB(0);
                com.google.android.gms.common.internal.zzu.zza(zzfy.this.zzfr(), "Unable to set the ad state error!");
                zzhsVar.zzf(null);
            }
        };
        zzbVar.zzBX = zzdgVar;
        zzbbVar.zza("/nativeAdPreProcess", zzdgVar);
        zzbbVar.zza("google.afma.nativeAds.preProcessJsonGmsg", new JSONObject(this.zzBs.zzFs.zzCI));
        return (JSONObject) zzhsVar.get(zzBF, TimeUnit.MILLISECONDS);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void zzb(zzcs zzcsVar, String str) {
        try {
            zzcw zzq = this.zzBH.zzq(zzcsVar.getCustomTemplateId());
            if (zzq != null) {
                zzq.zza(zzcsVar, str);
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Failed to call onCustomClick for asset " + str + ".", e);
        }
    }

    private String[] zzc(JSONObject jSONObject, String str) throws JSONException {
        JSONArray optJSONArray = jSONObject.optJSONArray(str);
        if (optJSONArray == null) {
            return null;
        }
        String[] strArr = new String[optJSONArray.length()];
        for (int i = 0; i < optJSONArray.length(); i++) {
            strArr[i] = optJSONArray.getString(i);
        }
        return strArr;
    }

    private zzbb zzfq() throws CancellationException, ExecutionException, InterruptedException, TimeoutException {
        if (zzfr()) {
            return null;
        }
        zzbb zzbbVar = this.zzBI.zza(this.mContext, this.zzBs.zzFr.zzpJ, (this.zzBs.zzFs.zzzG.indexOf("https") == 0 ? "https:" : "http:") + zzbz.zzur.get()).get(zzBF, TimeUnit.MILLISECONDS);
        zzbbVar.zza(this.zzBH, this.zzBH, this.zzBH, this.zzBH, false, null, null, null, null);
        return zzbbVar;
    }

    public void zzB(int i) {
        synchronized (this.zzqt) {
            this.zzBJ = true;
            this.zzBv = i;
        }
    }

    public zzhv<com.google.android.gms.ads.internal.formats.zzc> zza(JSONObject jSONObject, String str, boolean z, boolean z2) throws JSONException {
        JSONObject jSONObject2 = z ? jSONObject.getJSONObject(str) : jSONObject.optJSONObject(str);
        if (jSONObject2 == null) {
            jSONObject2 = new JSONObject();
        }
        return zza(jSONObject2, z, z2);
    }

    public List<zzhv<com.google.android.gms.ads.internal.formats.zzc>> zza(JSONObject jSONObject, String str, boolean z, boolean z2, boolean z3) throws JSONException {
        JSONArray jSONArray = z ? jSONObject.getJSONArray(str) : jSONObject.optJSONArray(str);
        ArrayList arrayList = new ArrayList();
        if (jSONArray == null || jSONArray.length() == 0) {
            zza(0, z);
            return arrayList;
        }
        int length = z3 ? jSONArray.length() : 1;
        for (int i = 0; i < length; i++) {
            JSONObject jSONObject2 = jSONArray.getJSONObject(i);
            if (jSONObject2 == null) {
                jSONObject2 = new JSONObject();
            }
            arrayList.add(zza(jSONObject2, z, z2));
        }
        return arrayList;
    }

    public Future<com.google.android.gms.ads.internal.formats.zzc> zza(JSONObject jSONObject, String str, boolean z) throws JSONException {
        JSONObject jSONObject2 = jSONObject.getJSONObject(str);
        boolean optBoolean = jSONObject2.optBoolean("require", true);
        if (jSONObject2 == null) {
            jSONObject2 = new JSONObject();
        }
        return zza(jSONObject2, optBoolean, z);
    }

    public void zza(int i, boolean z) {
        if (z) {
            zzB(i);
        }
    }

    protected zza zzd(JSONObject jSONObject) throws JSONException, TimeoutException {
        if (zzfr()) {
            return null;
        }
        String string = jSONObject.getString("template_id");
        boolean z = this.zzBs.zzFr.zzqb != null ? this.zzBs.zzFr.zzqb.zzvC : false;
        boolean z2 = this.zzBs.zzFr.zzqb != null ? this.zzBs.zzFr.zzqb.zzvE : false;
        if ("2".equals(string)) {
            return new zzfz(z, z2);
        }
        if ("1".equals(string)) {
            return new zzga(z, z2);
        }
        if ("3".equals(string)) {
            final String string2 = jSONObject.getString("custom_template_id");
            final zzhs zzhsVar = new zzhs();
            zzhl.zzGk.post(new Runnable() { // from class: com.google.android.gms.internal.zzfy.2
                @Override // java.lang.Runnable
                public void run() {
                    zzhsVar.zzf(zzfy.this.zzBH.zzbo().get(string2));
                }
            });
            if (zzhsVar.get(zzBF, TimeUnit.MILLISECONDS) != null) {
                return new zzgb(z);
            }
            com.google.android.gms.ads.internal.util.client.zzb.zzaz("No handler for custom template: " + jSONObject.getString("custom_template_id"));
        } else {
            zzB(0);
        }
        return null;
    }

    public zzhv<com.google.android.gms.ads.internal.formats.zza> zze(JSONObject jSONObject) throws JSONException {
        JSONObject optJSONObject = jSONObject.optJSONObject("attribution");
        if (optJSONObject == null) {
            return new zzht(null);
        }
        final String optString = optJSONObject.optString("text");
        final int optInt = optJSONObject.optInt("text_size", -1);
        final Integer zzb2 = zzb(optJSONObject, "text_color");
        final Integer zzb3 = zzb(optJSONObject, "bg_color");
        return zzhu.zza(zza(optJSONObject, "image", false, false), new zzhu.zza<com.google.android.gms.ads.internal.formats.zzc, com.google.android.gms.ads.internal.formats.zza>() { // from class: com.google.android.gms.internal.zzfy.4
            @Override // com.google.android.gms.internal.zzhu.zza
            /* renamed from: zza */
            public com.google.android.gms.ads.internal.formats.zza zze(com.google.android.gms.ads.internal.formats.zzc zzcVar) {
                com.google.android.gms.ads.internal.formats.zza zzaVar;
                if (zzcVar != null) {
                    try {
                        if (!TextUtils.isEmpty(optString)) {
                            zzaVar = new com.google.android.gms.ads.internal.formats.zza(optString, (Drawable) com.google.android.gms.dynamic.zze.zzn(zzcVar.zzdw()), zzb3, zzb2, optInt > 0 ? Integer.valueOf(optInt) : null);
                            return zzaVar;
                        }
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.zzb.zzb("Could not get attribution icon", e);
                        return null;
                    }
                }
                zzaVar = null;
                return zzaVar;
            }
        });
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0022  */
    @Override // java.util.concurrent.Callable
    /* renamed from: zzfp */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.zzha call() {
        /*
            r3 = this;
            com.google.android.gms.internal.zzbb r0 = r3.zzfq()     // Catch: org.json.JSONException -> L18 java.util.concurrent.TimeoutException -> L2c java.lang.InterruptedException -> L33 java.util.concurrent.ExecutionException -> L35 java.util.concurrent.CancellationException -> L37
            org.json.JSONObject r1 = r3.zzb(r0)     // Catch: org.json.JSONException -> L18 java.util.concurrent.TimeoutException -> L2c java.lang.InterruptedException -> L33 java.util.concurrent.ExecutionException -> L35 java.util.concurrent.CancellationException -> L37
            com.google.android.gms.internal.zzfy$zza r2 = r3.zzd(r1)     // Catch: org.json.JSONException -> L18 java.util.concurrent.TimeoutException -> L2c java.lang.InterruptedException -> L33 java.util.concurrent.ExecutionException -> L35 java.util.concurrent.CancellationException -> L37
            com.google.android.gms.ads.internal.formats.zzg$zza r1 = r3.zza(r0, r2, r1)     // Catch: org.json.JSONException -> L18 java.util.concurrent.TimeoutException -> L2c java.lang.InterruptedException -> L33 java.util.concurrent.ExecutionException -> L35 java.util.concurrent.CancellationException -> L37
            r3.zza(r1, r0)     // Catch: org.json.JSONException -> L18 java.util.concurrent.TimeoutException -> L2c java.lang.InterruptedException -> L33 java.util.concurrent.ExecutionException -> L35 java.util.concurrent.CancellationException -> L37
            com.google.android.gms.internal.zzha r0 = r3.zza(r1)     // Catch: org.json.JSONException -> L18 java.util.concurrent.TimeoutException -> L2c java.lang.InterruptedException -> L33 java.util.concurrent.ExecutionException -> L35 java.util.concurrent.CancellationException -> L37
        L17:
            return r0
        L18:
            r0 = move-exception
            java.lang.String r1 = "Malformed native JSON response."
            com.google.android.gms.ads.internal.util.client.zzb.zzd(r1, r0)
        L1e:
            boolean r0 = r3.zzBJ
            if (r0 != 0) goto L26
            r0 = 0
            r3.zzB(r0)
        L26:
            r0 = 0
            com.google.android.gms.internal.zzha r0 = r3.zza(r0)
            goto L17
        L2c:
            r0 = move-exception
            java.lang.String r1 = "Timeout when loading native ad."
            com.google.android.gms.ads.internal.util.client.zzb.zzd(r1, r0)
            goto L1e
        L33:
            r0 = move-exception
            goto L1e
        L35:
            r0 = move-exception
            goto L1e
        L37:
            r0 = move-exception
            goto L1e
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.zzfy.call():com.google.android.gms.internal.zzha");
    }

    public boolean zzfr() {
        boolean z;
        synchronized (this.zzqt) {
            z = this.zzBJ;
        }
        return z;
    }
}
