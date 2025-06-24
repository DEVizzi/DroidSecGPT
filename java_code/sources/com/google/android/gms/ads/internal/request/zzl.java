package com.google.android.gms.ads.internal.request;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import com.google.android.gms.ads.identifier.AdvertisingIdClient;
import com.google.android.gms.ads.internal.request.AdRequestInfoParcel;
import com.google.android.gms.ads.internal.request.zza;
import com.google.android.gms.ads.internal.zzo;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.internal.zzbb;
import com.google.android.gms.internal.zzbe;
import com.google.android.gms.internal.zzbr;
import com.google.android.gms.internal.zzbz;
import com.google.android.gms.internal.zzdg;
import com.google.android.gms.internal.zzdh;
import com.google.android.gms.internal.zzdl;
import com.google.android.gms.internal.zzdt;
import com.google.android.gms.internal.zzgd;
import com.google.android.gms.internal.zzgg;
import com.google.android.gms.internal.zzha;
import com.google.android.gms.internal.zzhh;
import com.google.android.gms.internal.zzhx;
import com.google.android.gms.internal.zzid;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.json.JSONException;
import org.json.JSONObject;
@zzgd
/* loaded from: classes.dex */
public class zzl extends zzhh {
    private final Context mContext;
    private final Object zzBr = new Object();
    private final zza.InterfaceC0014zza zzCd;
    private final AdRequestInfoParcel.zza zzCe;
    private zzdt.zzd zzDl;
    static final long zzDf = TimeUnit.SECONDS.toMillis(10);
    private static final Object zzoW = new Object();
    private static boolean zzDg = false;
    private static zzdt zzDh = null;
    private static zzdh zzDi = null;
    private static zzdl zzDj = null;
    private static zzdg zzDk = null;

    /* loaded from: classes.dex */
    public static class zza implements zzdt.zzb<zzbb> {
        @Override // com.google.android.gms.internal.zzdt.zzb
        /* renamed from: zza */
        public void zzc(zzbb zzbbVar) {
            zzl.zzd(zzbbVar);
        }
    }

    /* loaded from: classes.dex */
    public static class zzb implements zzdt.zzb<zzbb> {
        @Override // com.google.android.gms.internal.zzdt.zzb
        /* renamed from: zza */
        public void zzc(zzbb zzbbVar) {
            zzl.zzc(zzbbVar);
        }
    }

    /* loaded from: classes.dex */
    public static class zzc implements zzdg {
        @Override // com.google.android.gms.internal.zzdg
        public void zza(zzid zzidVar, Map<String, String> map) {
            com.google.android.gms.ads.internal.util.client.zzb.zzaC("Invalid request: " + map.get("errors"));
            zzl.zzDj.zzV(map.get("request_id"));
        }
    }

    public zzl(Context context, AdRequestInfoParcel.zza zzaVar, zza.InterfaceC0014zza interfaceC0014zza) {
        this.zzCd = interfaceC0014zza;
        this.mContext = context;
        this.zzCe = zzaVar;
        synchronized (zzoW) {
            if (!zzDg) {
                zzDj = new zzdl();
                zzDi = new zzdh(context.getApplicationContext(), zzaVar.zzpJ);
                zzDk = new zzc();
                zzDh = new zzdt(this.mContext.getApplicationContext(), this.zzCe.zzpJ, zzbz.zztD.get(), new zzb(), new zza());
                zzDg = true;
            }
        }
    }

    private JSONObject zza(AdRequestInfoParcel adRequestInfoParcel, String str) {
        JSONObject zza2;
        AdvertisingIdClient.Info info;
        Bundle bundle = adRequestInfoParcel.zzCm.extras.getBundle("sdk_less_server_data");
        String string = adRequestInfoParcel.zzCm.extras.getString("sdk_less_network_id");
        if (bundle == null || (zza2 = zzgg.zza(adRequestInfoParcel, zzo.zzbB().zzC(this.mContext), null, new zzbr(zzbz.zztD.get()), null, null, new ArrayList())) == null) {
            return null;
        }
        try {
            info = AdvertisingIdClient.getAdvertisingIdInfo(this.mContext);
        } catch (GooglePlayServicesNotAvailableException | GooglePlayServicesRepairableException | IOException | IllegalStateException e) {
            com.google.android.gms.ads.internal.util.client.zzb.zzd("Cannot get advertising id info", e);
            info = null;
        }
        HashMap hashMap = new HashMap();
        hashMap.put("request_id", str);
        hashMap.put("network_id", string);
        hashMap.put("request_param", zza2);
        hashMap.put("data", bundle);
        if (info != null) {
            hashMap.put("adid", info.getId());
            hashMap.put("lat", Integer.valueOf(info.isLimitAdTrackingEnabled() ? 1 : 0));
        }
        try {
            return zzo.zzbv().zzy(hashMap);
        } catch (JSONException e2) {
            return null;
        }
    }

    protected static void zzc(zzbb zzbbVar) {
        zzbbVar.zza("/loadAd", zzDj);
        zzbbVar.zza("/fetchHttpRequest", zzDi);
        zzbbVar.zza("/invalidRequest", zzDk);
    }

    protected static void zzd(zzbb zzbbVar) {
        zzbbVar.zzb("/loadAd", zzDj);
        zzbbVar.zzb("/fetchHttpRequest", zzDi);
        zzbbVar.zzb("/invalidRequest", zzDk);
    }

    private AdResponseParcel zzf(AdRequestInfoParcel adRequestInfoParcel) {
        final String uuid = UUID.randomUUID().toString();
        final JSONObject zza2 = zza(adRequestInfoParcel, uuid);
        if (zza2 == null) {
            return new AdResponseParcel(0);
        }
        long elapsedRealtime = zzo.zzbz().elapsedRealtime();
        Future<JSONObject> zzU = zzDj.zzU(uuid);
        com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.ads.internal.request.zzl.2
            @Override // java.lang.Runnable
            public void run() {
                zzl.this.zzDl = zzl.zzDh.zzdU();
                zzl.this.zzDl.zza(new zzhx.zzc<zzbe>() { // from class: com.google.android.gms.ads.internal.request.zzl.2.1
                    @Override // com.google.android.gms.internal.zzhx.zzc
                    /* renamed from: zzb */
                    public void zzc(zzbe zzbeVar) {
                        try {
                            zzbeVar.zza("AFMA_getAdapterLessMediationAd", zza2);
                        } catch (Exception e) {
                            com.google.android.gms.ads.internal.util.client.zzb.zzb("Error requesting an ad url", e);
                            zzl.zzDj.zzV(uuid);
                        }
                    }
                }, new zzhx.zza() { // from class: com.google.android.gms.ads.internal.request.zzl.2.2
                    @Override // com.google.android.gms.internal.zzhx.zza
                    public void run() {
                        zzl.zzDj.zzV(uuid);
                    }
                });
            }
        });
        try {
            JSONObject jSONObject = zzU.get(zzDf - (zzo.zzbz().elapsedRealtime() - elapsedRealtime), TimeUnit.MILLISECONDS);
            if (jSONObject == null) {
                return new AdResponseParcel(-1);
            }
            AdResponseParcel zza3 = zzgg.zza(this.mContext, adRequestInfoParcel, jSONObject.toString());
            return (zza3.errorCode == -3 || !TextUtils.isEmpty(zza3.zzCI)) ? zza3 : new AdResponseParcel(3);
        } catch (InterruptedException e) {
            return new AdResponseParcel(-1);
        } catch (CancellationException e2) {
            return new AdResponseParcel(-1);
        } catch (ExecutionException e3) {
            return new AdResponseParcel(0);
        } catch (TimeoutException e4) {
            return new AdResponseParcel(2);
        }
    }

    @Override // com.google.android.gms.internal.zzhh
    public void onStop() {
        synchronized (this.zzBr) {
            com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.ads.internal.request.zzl.3
                @Override // java.lang.Runnable
                public void run() {
                    if (zzl.this.zzDl != null) {
                        zzl.this.zzDl.release();
                        zzl.this.zzDl = null;
                    }
                }
            });
        }
    }

    @Override // com.google.android.gms.internal.zzhh
    public void zzdP() {
        com.google.android.gms.ads.internal.util.client.zzb.zzay("SdkLessAdLoaderBackgroundTask started.");
        AdRequestInfoParcel adRequestInfoParcel = new AdRequestInfoParcel(this.zzCe, null, null);
        AdResponseParcel zzf = zzf(adRequestInfoParcel);
        final zzha.zza zzaVar = new zzha.zza(adRequestInfoParcel, zzf, null, null, zzf.errorCode, zzo.zzbz().elapsedRealtime(), zzf.zzCO, null);
        com.google.android.gms.ads.internal.util.client.zza.zzGF.post(new Runnable() { // from class: com.google.android.gms.ads.internal.request.zzl.1
            @Override // java.lang.Runnable
            public void run() {
                zzl.this.zzCd.zza(zzaVar);
                if (zzl.this.zzDl != null) {
                    zzl.this.zzDl.release();
                    zzl.this.zzDl = null;
                }
            }
        });
    }
}
